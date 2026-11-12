//! Registry: owns the model list from `models.toml` and the load / evict lifecycle.
//!
//! * Nothing loads at startup. A model loads on its first request.
//! * Only one GGUF model is resident at a time; asking for another unloads the first.
//! * ONNX models stay cached; past `max_onnx_memory_mb` the least recently used is evicted.
//! * GGUF generations are queued through a semaphore (`max_concurrent_gguf`).

use std::{
    collections::HashMap,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::Serialize;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    config::{Config, ModelConfig, ModelKind},
    engines::{ClassifierEngine, EmbeddingEngine, EngineStatus, GenerativeEngine},
    errors::{ApiError, ApiResult, ErrorCode},
    metrics::{Metrics, ModelMetrics},
};

pub type Shared<T: ?Sized> = Arc<Mutex<Box<T>>>;

#[derive(Clone)]
enum Handle {
    Gen(Shared<dyn GenerativeEngine>),
    Emb(Shared<dyn EmbeddingEngine>),
    Cls(Shared<dyn ClassifierEngine>),
}

struct Loaded {
    handle: Handle,
    kind: ModelKind,
    mem_mb: u64,
    last_used_ms: AtomicU64,
}

#[derive(Debug, Clone, Default)]
struct StateInfo {
    loading: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelInfo {
    pub name: String,
    pub kind: ModelKind,
    pub status: EngineStatus,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dim: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Health {
    pub status: &'static str,
    pub uptime_secs: u64,
    pub loaded_models: Vec<String>,
    pub memory_mb_used: u64,
    pub models: Vec<ModelStatusLine>,
    pub evictions: u64,
    pub metrics: HashMap<String, ModelMetrics>,
}

#[derive(Debug, Serialize)]
pub struct ModelStatusLine {
    pub name: String,
    pub status: EngineStatus,
}

pub struct Registry {
    pub cfg: Arc<Config>,
    index: HashMap<String, usize>,
    loaded: RwLock<HashMap<String, Arc<Loaded>>>,
    states: RwLock<HashMap<String, StateInfo>>,
    load_lock: tokio::sync::Mutex<()>,
    gguf_gate: Arc<Semaphore>,
    pub metrics: Metrics,
    started: Instant,
}

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}
fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

impl Registry {
    pub fn new(cfg: Config) -> Arc<Self> {
        let index = cfg
            .models
            .iter()
            .enumerate()
            .map(|(i, m)| (m.name.clone(), i))
            .collect();
        let gate = Arc::new(Semaphore::new(cfg.server.max_concurrent_gguf));
        Arc::new(Self {
            cfg: Arc::new(cfg),
            index,
            loaded: RwLock::default(),
            states: RwLock::default(),
            load_lock: tokio::sync::Mutex::new(()),
            gguf_gate: gate,
            metrics: Metrics::default(),
            started: Instant::now(),
        })
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Look a model up by request name. The name is only ever a key into `models.toml`, never a path.
    pub fn model_config(&self, name: &str) -> ApiResult<&ModelConfig> {
        self.index
            .get(name)
            .map(|&i| &self.cfg.models[i])
            .ok_or_else(|| {
                ApiError::for_model(
                    ErrorCode::ModelNotFound,
                    name,
                    format!("Model '{name}' is not defined in models.toml"),
                )
            })
    }

    fn files_present(cfg: &ModelConfig) -> std::result::Result<(), String> {
        if !Path::new(&cfg.path).exists() {
            return Err(format!("model file not found: {}", cfg.path));
        }
        if let Some(t) = &cfg.tokenizer {
            if !Path::new(t).exists() {
                return Err(format!("tokenizer file not found: {t}"));
            }
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<ModelInfo> {
        let loaded = read(&self.loaded);
        let states = read(&self.states);
        self.cfg
            .models
            .iter()
            .map(|m| {
                let state = states.get(&m.name).cloned().unwrap_or_default();
                let live = loaded.get(&m.name);
                let status = if live.is_some() {
                    EngineStatus::Ready
                } else if state.loading {
                    EngineStatus::Loading
                } else if state.error.is_some() {
                    EngineStatus::Failed
                } else if Self::files_present(m).is_err() {
                    EngineStatus::Missing
                } else {
                    EngineStatus::Unloaded
                };
                ModelInfo {
                    name: m.name.clone(),
                    kind: m.kind,
                    status,
                    path: m.path.clone(),
                    description: m.description.clone(),
                    dim: m.dim,
                    labels: m.labels.clone(),
                    threshold: m.threshold,
                    memory_mb: live.map(|l| l.mem_mb),
                    error: state
                        .error
                        .or_else(|| Self::files_present(m).err().filter(|_| live.is_none())),
                }
            })
            .collect()
    }

    pub fn health(&self) -> Health {
        let models = self.list();
        let loaded = read(&self.loaded);
        let mut names: Vec<String> = loaded.keys().cloned().collect();
        names.sort();
        Health {
            status: "ok",
            uptime_secs: self.started.elapsed().as_secs(),
            loaded_models: names,
            memory_mb_used: loaded.values().map(|l| l.mem_mb).sum(),
            models: models
                .into_iter()
                .map(|m| ModelStatusLine {
                    name: m.name,
                    status: m.status,
                })
                .collect(),
            evictions: self.metrics.evictions(),
            metrics: self.metrics.snapshot(),
        }
    }

    /// Wait for a generation slot. Counts against the request deadline.
    pub async fn gguf_permit(&self, deadline: Instant) -> ApiResult<OwnedSemaphorePermit> {
        let wait = deadline.saturating_duration_since(Instant::now());
        match tokio::time::timeout(wait, self.gguf_gate.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(ApiError::internal("generation queue closed")),
            Err(_) => Err(ApiError::new(
                ErrorCode::Timeout,
                "timed out waiting for the generation queue",
            )),
        }
    }

    pub async fn generative(&self, name: &str) -> ApiResult<Shared<dyn GenerativeEngine>> {
        match self.ensure(name, ModelKind::Gguf).await? {
            Handle::Gen(h) => Ok(h),
            _ => Err(ApiError::internal("registry returned the wrong engine type")),
        }
    }

    pub async fn embedding(&self, name: &str) -> ApiResult<Shared<dyn EmbeddingEngine>> {
        match self.ensure(name, ModelKind::Embedding).await? {
            Handle::Emb(h) => Ok(h),
            _ => Err(ApiError::internal("registry returned the wrong engine type")),
        }
    }

    pub async fn classifier(&self, name: &str) -> ApiResult<Shared<dyn ClassifierEngine>> {
        match self.ensure(name, ModelKind::Classifier).await? {
            Handle::Cls(h) => Ok(h),
            _ => Err(ApiError::internal("registry returned the wrong engine type")),
        }
    }

    fn touch_live(&self, name: &str) -> Option<Handle> {
        let loaded = read(&self.loaded);
        loaded.get(name).map(|l| {
            l.last_used_ms.store(self.now_ms(), Ordering::Relaxed);
            l.handle.clone()
        })
    }

    async fn ensure(&self, name: &str, want: ModelKind) -> ApiResult<Handle> {
        let mc = self.model_config(name)?;
        if mc.kind != want {
            return Err(ApiError::for_model(
                ErrorCode::InvalidRequest,
                name,
                format!(
                    "Model '{name}' is a {} model and cannot be used for this endpoint",
                    mc.kind.as_str()
                ),
            ));
        }
        if let Some(h) = self.touch_live(name) {
            return Ok(h);
        }

        // Slow path: one load at a time, so two requests never load the same model twice.
        let _guard = self.load_lock.lock().await;
        if let Some(h) = self.touch_live(name) {
            return Ok(h);
        }
        if let Err(msg) = Self::files_present(mc) {
            return Err(ApiError::for_model(ErrorCode::ModelNotReady, name, msg));
        }

        write(&self.states).insert(
            name.to_string(),
            StateInfo {
                loading: true,
                error: None,
            },
        );
        let started = Instant::now();
        let cfg = mc.clone();
        let result = tokio::task::spawn_blocking(move || load_engine(&cfg)).await;

        let (handle, mem_mb) = match result {
            Ok(Ok(ok)) => ok,
            Ok(Err(e)) => return Err(self.load_failed(name, format!("{e:#}"))),
            Err(e) => return Err(self.load_failed(name, format!("loader thread crashed: {e}"))),
        };

        let load_ms = started.elapsed().as_millis() as u64;
        self.metrics.record_load(name, load_ms);
        tracing::info!(model = %name, load_ms, memory_mb = mem_mb, "model loaded");

        {
            let mut loaded = write(&self.loaded);
            if mc.kind == ModelKind::Gguf {
                // Only one GGUF resident at a time.
                let others: Vec<String> = loaded
                    .iter()
                    .filter(|(k, l)| l.kind == ModelKind::Gguf && k.as_str() != name)
                    .map(|(k, _)| k.clone())
                    .collect();
                for other in others {
                    loaded.remove(&other);
                    self.metrics.record_eviction();
                    tracing::info!(model = %other, reason = "another gguf requested", "model unloaded");
                }
            }
            loaded.insert(
                name.to_string(),
                Arc::new(Loaded {
                    handle: handle.clone(),
                    kind: mc.kind,
                    mem_mb,
                    last_used_ms: AtomicU64::new(self.now_ms()),
                }),
            );
            self.evict_onnx_over_budget(&mut loaded, name);
        }
        write(&self.states).remove(name);
        Ok(handle)
    }

    fn load_failed(&self, name: &str, message: String) -> ApiError {
        tracing::error!(model = %name, error = %message, "model load failed");
        write(&self.states).insert(
            name.to_string(),
            StateInfo {
                loading: false,
                error: Some(message.clone()),
            },
        );
        ApiError::for_model(ErrorCode::ModelLoadFailed, name, message)
    }

    fn evict_onnx_over_budget(&self, loaded: &mut HashMap<String, Arc<Loaded>>, keep: &str) {
        let limit = self.cfg.server.max_onnx_memory_mb;
        loop {
            let total: u64 = loaded
                .values()
                .filter(|l| l.kind != ModelKind::Gguf)
                .map(|l| l.mem_mb)
                .sum();
            if total <= limit {
                return;
            }
            let victim = loaded
                .iter()
                .filter(|(k, l)| l.kind != ModelKind::Gguf && k.as_str() != keep)
                .min_by_key(|(_, l)| l.last_used_ms.load(Ordering::Relaxed))
                .map(|(k, _)| k.clone());
            match victim {
                Some(v) => {
                    loaded.remove(&v);
                    self.metrics.record_eviction();
                    tracing::info!(model = %v, reason = "onnx memory budget", "model unloaded");
                }
                None => return,
            }
        }
    }

    /// Unload GGUF models idle longer than `gguf_idle_unload_secs`.
    pub fn sweep_idle(&self) {
        let secs = self.cfg.server.gguf_idle_unload_secs;
        if secs == 0 {
            return;
        }
        let idle_limit = Duration::from_secs(secs).as_millis() as u64;
        let now = self.now_ms();
        let mut loaded = write(&self.loaded);
        let stale: Vec<String> = loaded
            .iter()
            .filter(|(_, l)| {
                l.kind == ModelKind::Gguf
                    && now.saturating_sub(l.last_used_ms.load(Ordering::Relaxed)) > idle_limit
            })
            .map(|(k, _)| k.clone())
            .collect();
        for name in stale {
            loaded.remove(&name);
            self.metrics.record_eviction();
            tracing::info!(model = %name, reason = "idle", "model unloaded");
        }
    }
}

fn load_engine(cfg: &ModelConfig) -> Result<(Handle, u64)> {
    match cfg.kind {
        ModelKind::Gguf => load_gguf(cfg),
        ModelKind::Embedding | ModelKind::Classifier => load_onnx(cfg),
    }
}

#[cfg(feature = "gguf")]
fn load_gguf(cfg: &ModelConfig) -> Result<(Handle, u64)> {
    use crate::engines::{gguf::GgufEngine, Engine};
    let engine = GgufEngine::load(cfg)?;
    let mem = engine.memory_mb();
    Ok((Handle::Gen(Arc::new(Mutex::new(Box::new(engine) as Box<dyn GenerativeEngine>))), mem))
}

#[cfg(not(feature = "gguf"))]
fn load_gguf(_cfg: &ModelConfig) -> Result<(Handle, u64)> {
    anyhow::bail!("this binary was built without the `gguf` feature")
}

#[cfg(feature = "onnx")]
fn load_onnx(cfg: &ModelConfig) -> Result<(Handle, u64)> {
    use crate::engines::{onnx::OnnxEngine, Engine};
    let engine = OnnxEngine::load(cfg)?;
    let mem = engine.memory_mb();
    let handle = if cfg.kind == ModelKind::Embedding {
        Handle::Emb(Arc::new(Mutex::new(Box::new(engine) as Box<dyn EmbeddingEngine>)))
    } else {
        Handle::Cls(Arc::new(Mutex::new(Box::new(engine) as Box<dyn ClassifierEngine>)))
    };
    Ok((handle, mem))
}

#[cfg(not(feature = "onnx"))]
fn load_onnx(_cfg: &ModelConfig) -> Result<(Handle, u64)> {
    anyhow::bail!("this binary was built without the `onnx` feature")
}
