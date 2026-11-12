#![allow(dead_code)]
//! Engine traits. The registry treats every engine the same through `Engine`;
//! the three capability traits are what the API layer calls.

#[cfg(feature = "gguf")]
pub mod gguf;
#[cfg(feature = "onnx")]
pub mod onnx;

use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::config::ModelKind;
use crate::errors::ApiError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EngineStatus {
    Unloaded,
    Loading,
    Ready,
    Failed,
    Missing,
}

pub trait Engine: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> ModelKind;
    fn status(&self) -> EngineStatus {
        EngineStatus::Ready
    }
    /// Estimated resident memory in MB.
    fn memory_mb(&self) -> u64;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct GenerateRequest {
    pub messages: Vec<ChatMessage>,
    pub temperature: f32,
    pub top_p: f32,
    pub max_tokens: usize,
    pub stop: Vec<String>,
    /// Constrain output to valid JSON.
    pub json: bool,
    /// Generation stops with `FinishReason::Timeout` once this passes.
    pub deadline: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FinishReason {
    Stop,
    Length,
    Timeout,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct GenerateResponse {
    pub text: String,
    pub prompt_tokens: usize,
    pub completion_tokens: usize,
    pub finish_reason: FinishReason,
}

pub trait GenerativeEngine: Engine {
    /// Generate a completion. Every visible piece of text is passed to `sink`;
    /// return `false` from `sink` to cancel (for example when an SSE client left).
    /// Non-streaming callers pass a sink that ignores the pieces and read `text` instead.
    fn generate(
        &mut self,
        req: &GenerateRequest,
        sink: &mut dyn FnMut(&str) -> bool,
    ) -> Result<GenerateResponse, ApiError>;
}

pub trait EmbeddingEngine: Engine {
    fn dim(&self) -> usize;
    fn embed_batch(&mut self, texts: &[String]) -> Result<Vec<Vec<f32>>, ApiError>;
}

#[derive(Debug, Clone, Serialize)]
pub struct Classification {
    pub label: String,
    pub score: f32,
    pub all_scores: Vec<(String, f32)>,
}

pub trait ClassifierEngine: Engine {
    fn labels(&self) -> &[String];
    fn classify(&mut self, text: &str) -> Result<Classification, ApiError>;
}
