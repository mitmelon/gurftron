/**
 * Gurftron LLM Engine: Real local AI inference with llama.cpp
 */
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use sysinfo::{System, SystemExt};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use std::time::{Duration, Instant};
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::{LlamaModel, AddBos};
use llama_cpp_2::context::LlamaContext;
use llama_cpp_2::token::data_array::LlamaTokenDataArray;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub name: String,
    pub repo_id: String,
    pub filename: String,
    pub min_ram_gb: u64,
    pub size_mb: u64,
    pub description: String,
    pub quantization: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "system", "user", "assistant"
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionRequest {
    pub messages: Vec<ChatMessage>,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
    #[serde(default = "default_top_p")]
    pub top_p: f32,
    #[serde(default)]
    pub stream: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Choice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

fn default_max_tokens() -> u32 { 512 }
fn default_temperature() -> f32 { 0.7 }
fn default_top_p() -> f32 { 0.9 }

pub struct LLMEngine {
    backend: LlamaBackend,
    model: Arc<LlamaModel>,
    context: Arc<Mutex<LlamaContext>>,
    model_config: ModelConfig,
    context_size: u32,
}

impl LLMEngine {
    pub fn get_available_models() -> Vec<ModelConfig> {
        vec![
            ModelConfig {
                name: "TinyLlama-1.1B".to_string(),
                repo_id: "TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF".to_string(),
                filename: "tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf".to_string(),
                min_ram_gb: 2,
                size_mb: 669,
                description: "Fast lightweight model".to_string(),
                quantization: "Q4_K_M".to_string(),
            },
            ModelConfig {
                name: "Phi-2-2.7B".to_string(),
                repo_id: "TheBloke/phi-2-GGUF".to_string(),
                filename: "phi-2.Q4_K_M.gguf".to_string(),
                min_ram_gb: 4,
                size_mb: 1560,
                description: "Balanced performance".to_string(),
                quantization: "Q4_K_M".to_string(),
            },
            ModelConfig {
                name: "Mistral-7B-Instruct".to_string(),
                repo_id: "TheBloke/Mistral-7B-Instruct-v0.2-GGUF".to_string(),
                filename: "mistral-7b-instruct-v0.2.Q4_K_M.gguf".to_string(),
                min_ram_gb: 8,
                size_mb: 4370,
                description: "High quality responses".to_string(),
                quantization: "Q4_K_M".to_string(),
            },
            ModelConfig {
                name: "Llama-3-8B-Instruct".to_string(),
                repo_id: "bartowski/Meta-Llama-3-8B-Instruct-GGUF".to_string(),
                filename: "Meta-Llama-3-8B-Instruct-Q4_K_M.gguf".to_string(),
                min_ram_gb: 16,
                size_mb: 4920,
                description: "State-of-the-art model".to_string(),
                quantization: "Q4_K_M".to_string(),
            },
        ]
    }

    pub fn detect_best_model() -> ModelConfig {
        let mut sys = System::new_all();
        sys.refresh_all();
        
        let total_ram_gb = sys.total_memory() / (1024 * 1024 * 1024);
        let usable_ram = total_ram_gb.saturating_sub(2);
        
        info!("System RAM: {} GB total, selecting model for {} GB", total_ram_gb, usable_ram);
        
        let models = Self::get_available_models();
        for model in models.iter().rev() {
            if model.min_ram_gb <= usable_ram {
                info!("Selected: {} ({}GB RAM)", model.name, model.min_ram_gb);
                return model.clone();
            }
        }
        
        warn!("Using smallest model due to low RAM");
        models[0].clone()
    }

    pub async fn download_model(config: &ModelConfig, target_dir: &Path) -> Result<PathBuf, Box<dyn Error + Send + Sync>> {
        fs::create_dir_all(target_dir).await?;
        let model_path = target_dir.join(&config.filename);
        
        if model_path.exists() {
            let file_size = fs::metadata(&model_path).await?.len();
            let expected_size = (config.size_mb as u64) * 1024 * 1024;
            if file_size >= expected_size * 95 / 100 {
                info!("Model already exists: {}", model_path.display());
                return Ok(model_path);
            }
            fs::remove_file(&model_path).await.ok();
        }
        
        let url = format!("https://huggingface.co/{}/resolve/main/{}", config.repo_id, config.filename);
        info!("Downloading {} from: {}", config.name, url);
        
        let client = reqwest::Client::builder()
            .user_agent("Gurftron-LLM/2.2")
            .timeout(Duration::from_secs(3600))
            .tcp_nodelay(true)
            .build()?;
        
        let response = client.get(&url).send().await?;
        if !response.status().is_success() {
            return Err(format!("Download failed: HTTP {}", response.status()).into());
        }
        
        let total_size = response.content_length().unwrap_or(config.size_mb as u64 * 1024 * 1024);
        let pb = ProgressBar::new(total_size);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")?
                .progress_chars("#>-")
        );
        pb.set_message(format!("Downloading {}", config.name));
        
        let mut file = fs::File::create(&model_path).await?;
        let mut downloaded: u64 = 0;
        let mut stream = response.bytes_stream();
        
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            file.write_all(&chunk).await?;
            downloaded += chunk.len() as u64;
            pb.set_position(downloaded);
        }
        
        pb.finish_with_message(format!("Downloaded {}", config.name));
        Ok(model_path)
    }

    pub async fn new(model_dir: &Path) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let config = Self::detect_best_model();
        let model_path = Self::download_model(&config, model_dir).await?;
        
        info!("Loading model into memory...");
        let backend = LlamaBackend::init().map_err(|e| format!("Backend init failed: {}", e))?;
        
        let model = LlamaModel::load_from_file(&backend, model_path, &Default::default())
            .map_err(|e| format!("Model load failed: {}", e))?;
        
        let mut sys = System::new_all();
        sys.refresh_all();
        let available_ram_gb = sys.available_memory() / (1024 * 1024 * 1024);
        
        let context_size = if available_ram_gb >= 16 { 4096 }
                           else if available_ram_gb >= 8 { 2048 }
                           else { 1024 };
        
        let mut ctx_params = LlamaContextParams::default();
        ctx_params.n_ctx(Some(context_size));
        ctx_params.n_batch(512);
        ctx_params.n_threads(num_cpus::get() as u32);
        
        let context = model.new_context(&backend, ctx_params)
            .map_err(|e| format!("Context creation failed: {}", e))?;
        
        info!("✅ LLM ready: {} (context: {})", config.name, context_size);
        
        Ok(Self {
            backend,
            model: Arc::new(model),
            context: Arc::new(Mutex::new(context)),
            model_config: config,
            context_size,
        })
    }

    fn format_prompt(&self, messages: &[ChatMessage]) -> String {
        let mut prompt = String::new();
        
        // Llama-3 / Mistral / Phi-2 compatible format
        for msg in messages {
            match msg.role.as_str() {
                "system" => prompt.push_str(&format!("<|system|>\n{}\n", msg.content)),
                "user" => prompt.push_str(&format!("<|user|>\n{}\n", msg.content)),
                "assistant" => prompt.push_str(&format!("<|assistant|>\n{}\n", msg.content)),
                _ => {}
            }
        }
        prompt.push_str("<|assistant|>\n");
        prompt
    }

    pub async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, Box<dyn Error + Send + Sync>> {
        let start_time = Instant::now();
        let prompt = self.format_prompt(&request.messages);
        
        info!("Processing completion request ({} tokens max)", request.max_tokens);
        
        let mut ctx = self.context.lock().await;
        
        // Tokenize prompt
        let prompt_tokens = self.model.str_to_token(&prompt, AddBos::Always)
            .map_err(|e| format!("Tokenization failed: {}", e))?;
        
        let prompt_token_count = prompt_tokens.len() as u32;
        info!("Prompt tokens: {}", prompt_token_count);
        
        // Create batch
        let mut batch = LlamaBatch::new(self.context_size as usize, 1);
        
        // Add prompt tokens to batch
        for (i, token) in prompt_tokens.iter().enumerate() {
            let is_last = i == prompt_tokens.len() - 1;
            batch.add(*token, i as i32, &[0], is_last)
                .map_err(|e| format!("Batch add failed: {}", e))?;
        }
        
        // Decode prompt
        ctx.decode(&mut batch).map_err(|e| format!("Decode failed: {}", e))?;
        
        // Generate completion
        let mut generated_tokens = Vec::new();
        let mut n_cur = prompt_tokens.len();
        let n_len = request.max_tokens as usize;
        
        while n_cur <= n_len {
            // Sample next token
            let candidates = ctx.candidates_ith(batch.n_tokens() - 1);
            
            let mut candidates_p = LlamaTokenDataArray::from_iter(candidates, false);
            
            // Apply temperature
            candidates_p.sample_top_p(&mut ctx, request.top_p, 1);
            candidates_p.sample_temp(&mut ctx, request.temperature);
            let new_token_id = candidates_p.sample_token(&mut ctx);
            
            // Check for EOS
            if self.model.is_eog_token(new_token_id) {
                break;
            }
            
            generated_tokens.push(new_token_id);
            
            // Prepare next batch
            batch.clear();
            batch.add(new_token_id, n_cur as i32, &[0], true)
                .map_err(|e| format!("Batch add failed: {}", e))?;
            
            n_cur += 1;
            
            // Decode
            ctx.decode(&mut batch).map_err(|e| format!("Decode failed: {}", e))?;
        }
        
        // Convert tokens to string
        let generated_text = self.model.tokens_to_str(&generated_tokens)
            .map_err(|e| format!("Token conversion failed: {}", e))?
            .trim()
            .to_string();
        
        let completion_tokens = generated_tokens.len() as u32;
        let total_tokens = prompt_token_count + completion_tokens;
        
        info!("Generated {} tokens in {:?}", completion_tokens, start_time.elapsed());
        
        Ok(CompletionResponse {
            id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
            object: "chat.completion".to_string(),
            created: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            model: self.model_config.name.clone(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: generated_text,
                },
                finish_reason: "stop".to_string(),
            }],
            usage: Usage {
                prompt_tokens: prompt_token_count,
                completion_tokens,
                total_tokens,
            },
        })
    }

    pub fn get_model_info(&self) -> ModelConfig {
        self.model_config.clone()
    }
}