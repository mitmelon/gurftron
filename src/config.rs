//! Configuration: `server.toml` (how the process runs) and `models.toml` (what it can load).

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_concurrent_gguf: usize,
    pub request_timeout_secs: u64,
    pub log_level: String,
    /// Unload the GGUF model after this many idle seconds. 0 disables.
    pub gguf_idle_unload_secs: u64,
    /// When the estimated memory of loaded ONNX models passes this, evict least recently used.
    pub max_onnx_memory_mb: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 3000,
            max_concurrent_gguf: 1,
            request_timeout_secs: 60,
            log_level: "info".into(),
            gguf_idle_unload_secs: 300,
            max_onnx_memory_mb: 800,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Limits {
    pub max_prompt_chars: usize,
    pub max_output_tokens: usize,
    pub max_batch_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_prompt_chars: 20_000,
            max_output_tokens: 1024,
            max_batch_size: 8,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ServerFile {
    pub server: ServerConfig,
    pub limits: Limits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelKind {
    Gguf,
    Embedding,
    Classifier,
}

impl ModelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ModelKind::Gguf => "gguf",
            ModelKind::Embedding => "embedding",
            ModelKind::Classifier => "classifier",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelConfig {
    pub name: String,
    pub path: String,
    pub tokenizer: Option<String>,
    pub kind: ModelKind,
    pub description: Option<String>,

    // GGUF
    pub n_ctx: Option<usize>,
    pub n_threads: Option<usize>,
    pub temperature_default: Option<f32>,
    pub top_p_default: Option<f32>,
    /// chatml | qwen3 | gemma | llama3 | mistral | plain (default chatml)
    pub chat_template: Option<String>,

    // ONNX
    pub dim: Option<usize>,
    pub labels: Option<Vec<String>>,
    pub threshold: Option<f32>,
    pub pooling: Option<String>,
    pub normalize: Option<bool>,
    pub max_length: Option<usize>,
    /// Labels that count as harmless when this classifier is used as a guard (default ["SAFE"]).
    pub safe_labels: Option<Vec<String>>,
    /// Guard only: block when the top score is below `threshold` (default true, fail safe).
    pub block_on_uncertain: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ModelsFile {
    #[serde(default, rename = "model")]
    models: Vec<ModelConfig>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub limits: Limits,
    pub models: Vec<ModelConfig>,
}

impl ModelConfig {
    pub fn resolved_path(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }
    pub fn resolved_tokenizer(&self) -> Option<PathBuf> {
        self.tokenizer.as_ref().map(PathBuf::from)
    }
}

fn is_kebab(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Load both config files. Relative model paths are resolved against the folder holding `models.toml`.
pub fn load(server_path: &Path, models_path: &Path) -> Result<Config> {
    let ServerFile { mut server, limits } = if server_path.exists() {
        let text = fs::read_to_string(server_path)
            .with_context(|| format!("reading {}", server_path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing {}", server_path.display()))?
    } else {
        ServerFile::default()
    };

    if let Ok(host) = std::env::var("MANOMITE_HOST") {
        server.host = host;
    }
    if let Ok(port) = std::env::var("MANOMITE_PORT") {
        server.port = port.parse().context("MANOMITE_PORT must be a port number")?;
    }
    if server.max_concurrent_gguf == 0 {
        bail!("server.max_concurrent_gguf must be at least 1");
    }

    let text = fs::read_to_string(models_path)
        .with_context(|| format!("reading {}", models_path.display()))?;
    let parsed: ModelsFile =
        toml::from_str(&text).with_context(|| format!("parsing {}", models_path.display()))?;

    let base = models_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut seen = HashSet::new();
    let mut models = parsed.models;
    for m in &mut models {
        if !is_kebab(&m.name) {
            bail!("model name '{}' must be lowercase kebab-case", m.name);
        }
        if !seen.insert(m.name.clone()) {
            bail!("duplicate model name '{}'", m.name);
        }
        m.path = base.join(&m.path).to_string_lossy().into_owned();
        if let Some(t) = &m.tokenizer {
            m.tokenizer = Some(base.join(t).to_string_lossy().into_owned());
        }
        if m.kind != ModelKind::Gguf && m.tokenizer.is_none() {
            bail!("model '{}' needs a `tokenizer` path", m.name);
        }
    }

    Ok(Config {
        server,
        limits,
        models,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kebab_names() {
        assert!(is_kebab("qwen3-0-6b"));
        assert!(!is_kebab("Qwen"));
        assert!(!is_kebab("-a"));
        assert!(!is_kebab("a b"));
        assert!(!is_kebab("../etc"));
    }

    #[test]
    fn missing_models_file_errors() {
        let r = load(Path::new("nope-server.toml"), Path::new("nope-models.toml"));
        assert!(r.is_err());
    }

    #[test]
    fn parses_models() {
        let dir = std::env::temp_dir().join(format!("manomite-cfg-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("models.toml");
        fs::write(
            &p,
            r#"
[[model]]
name = "a"
path = "models/a.gguf"
kind = "gguf"

[[model]]
name = "b"
path = "models/b/model.onnx"
tokenizer = "models/b/tokenizer.json"
kind = "embedding"
dim = 384
"#,
        )
        .unwrap();
        let cfg = load(&dir.join("server.toml"), &p).unwrap();
        assert_eq!(cfg.models.len(), 2);
        assert!(cfg.models[0].path.ends_with("models/a.gguf"));
        assert_eq!(cfg.server.port, 3000);
    }
}
