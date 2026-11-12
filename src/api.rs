//! HTTP layer: routes, request validation, and the single error shape.

use std::{
    convert::Infallible,
    sync::{Arc, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    extract::{FromRequest, Request, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::{
    engines::{ChatMessage, Classification, FinishReason, GenerateRequest},
    errors::{ApiError, ApiResult, ErrorCode},
    registry::Registry,
};

type AppState = Arc<Registry>;

pub fn router(registry: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/guard", post(guard))
        .route("/v1/classify", post(classify))
        .fallback(not_found)
        .with_state(registry)
}

/// `Json<T>` whose rejections use the API error shape.
pub struct ApiJson<T>(pub T);

#[axum::async_trait]
impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(v)) => Ok(ApiJson(v)),
            Err(e) => Err(ApiError::invalid(e.body_text())),
        }
    }
}

async fn not_found() -> Response {
    let body = json!({ "error": { "code": "INVALID_REQUEST", "message": "No such route", "model": null } });
    (axum::http::StatusCode::NOT_FOUND, Json(body)).into_response()
}

async fn health(State(reg): State<AppState>) -> impl IntoResponse {
    Json(reg.health())
}

async fn models(State(reg): State<AppState>) -> impl IntoResponse {
    Json(json!({ "models": reg.list() }))
}

// ---------- helpers ----------

fn deadline(reg: &Registry) -> Instant {
    Instant::now() + Duration::from_secs(reg.cfg.server.request_timeout_secs)
}

fn check_text(reg: &Registry, text: &str) -> ApiResult<()> {
    if text.trim().is_empty() {
        return Err(ApiError::invalid("input must not be empty"));
    }
    if text.chars().count() > reg.cfg.limits.max_prompt_chars {
        return Err(ApiError::new(
            ErrorCode::PromptTooLong,
            format!(
                "input is longer than {} characters",
                reg.cfg.limits.max_prompt_chars
            ),
        ));
    }
    Ok(())
}

/// Run blocking inference off the async runtime, bounded by the request deadline.
async fn blocking<T, F>(deadline: Instant, f: F) -> ApiResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ApiResult<T> + Send + 'static,
{
    let wait = deadline.saturating_duration_since(Instant::now());
    match tokio::time::timeout(wait, tokio::task::spawn_blocking(f)).await {
        Ok(Ok(result)) => result,
        Ok(Err(e)) => Err(ApiError::internal(format!("inference thread crashed: {e}"))),
        Err(_) => Err(ApiError::new(ErrorCode::Timeout, "request timed out")),
    }
}

fn log_outcome<T>(reg: &Registry, model: &str, started: Instant, result: &ApiResult<T>) {
    reg.metrics
        .record_request(model, started.elapsed().as_millis() as u64, result.is_ok());
}

// ---------- chat ----------

#[derive(Deserialize)]
#[serde(untagged)]
enum StopField {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: Option<f32>,
    top_p: Option<f32>,
    max_tokens: Option<usize>,
    stop: Option<StopField>,
    stream: Option<bool>,
    format: Option<String>,
    /// Optional: name of a guard model. Every user message is checked first.
    guard: Option<String>,
}

async fn chat(State(reg): State<AppState>, ApiJson(body): ApiJson<ChatRequest>) -> ApiResult<Response> {
    let started = Instant::now();
    let deadline = deadline(&reg);
    let model_cfg = reg.model_config(&body.model)?.clone();
    let model = body.model.clone();

    // Validate before touching any model.
    if body.messages.is_empty() {
        return Err(ApiError::invalid("messages must not be empty"));
    }
    let mut total = 0usize;
    for m in &body.messages {
        if !matches!(m.role.as_str(), "system" | "user" | "assistant") {
            return Err(ApiError::invalid(format!("unknown role '{}'", m.role)));
        }
        total += m.content.chars().count();
    }
    if total > reg.cfg.limits.max_prompt_chars {
        return Err(ApiError::new(
            ErrorCode::PromptTooLong,
            format!("messages are longer than {} characters", reg.cfg.limits.max_prompt_chars),
        ));
    }
    if body.messages.last().is_some_and(|m| m.role == "assistant") {
        return Err(ApiError::invalid("the last message must be from the system or user"));
    }
    let json_mode = match body.format.as_deref() {
        None | Some("text") => false,
        Some("json") => true,
        Some(other) => return Err(ApiError::invalid(format!("unsupported format '{other}'"))),
    };
    let temperature = body
        .temperature
        .or(model_cfg.temperature_default)
        .unwrap_or(0.7);
    if !(0.0..=2.0).contains(&temperature) {
        return Err(ApiError::invalid("temperature must be between 0 and 2"));
    }
    let max_tokens = body
        .max_tokens
        .unwrap_or(256)
        .clamp(1, reg.cfg.limits.max_output_tokens);
    let stop = match body.stop {
        None => Vec::new(),
        Some(StopField::One(s)) => vec![s],
        Some(StopField::Many(v)) => v,
    };
    if stop.len() > 8 {
        return Err(ApiError::invalid("at most 8 stop strings"));
    }

    // Optional guard: fail safe, a guard error stops the request too.
    if let Some(guard_model) = &body.guard {
        for m in body.messages.iter().filter(|m| m.role == "user") {
            let verdict = run_guard(&reg, guard_model, &m.content, deadline).await?;
            if verdict.blocked {
                return Err(ApiError::for_model(
                    ErrorCode::GuardBlocked,
                    guard_model,
                    format!("Input blocked by guard ({} {:.2})", verdict.label, verdict.score),
                ));
            }
        }
    }

    // Queue for the single generation slot, then make sure the model is loaded.
    let permit = reg.gguf_permit(deadline).await?;
    let engine = reg.generative(&model).await?;

    let req = GenerateRequest {
        messages: body.messages,
        temperature,
        top_p: body.top_p.or(model_cfg.top_p_default).unwrap_or(0.9),
        max_tokens,
        stop,
        json: json_mode,
        deadline,
    };

    if body.stream.unwrap_or(false) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<Event, Infallible>>();
        let reg2 = reg.clone();
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut guard = engine.lock().unwrap_or_else(PoisonError::into_inner);
            let mut sink = |piece: &str| {
                tx.send(Ok(Event::default().data(json!({ "token": piece }).to_string())))
                    .is_ok()
            };
            let result = guard.generate(&req, &mut sink);
            let ok = match &result {
                Ok(r) if r.finish_reason == FinishReason::Timeout => {
                    let err = json!({"error": {"code": "TIMEOUT", "message": "request timed out", "model": model}});
                    let _ = tx.send(Ok(Event::default().data(err.to_string())));
                    false
                }
                Ok(_) => true,
                Err(e) => {
                    let err = json!({"error": {"code": e.code.as_str(), "message": e.message, "model": model}});
                    let _ = tx.send(Ok(Event::default().data(err.to_string())));
                    false
                }
            };
            let _ = tx.send(Ok(Event::default().data("[DONE]")));
            reg2.metrics
                .record_request(&model, started.elapsed().as_millis() as u64, ok);
            if let Ok(r) = &result {
                tracing::info!(
                    model = %model,
                    prompt_tokens = r.prompt_tokens,
                    completion_tokens = r.completion_tokens,
                    duration_ms = started.elapsed().as_millis() as u64,
                    stream = true,
                    "chat"
                );
            }
        });
        return Ok(Sse::new(UnboundedReceiverStream::new(rx))
            .keep_alive(KeepAlive::default())
            .into_response());
    }

    let result = blocking(deadline + Duration::from_secs(1), move || {
        let _permit = permit;
        let mut guard = engine.lock().unwrap_or_else(PoisonError::into_inner);
        guard.generate(&req, &mut |_| true)
    })
    .await;
    log_outcome(&reg, &model, started, &result);
    let r = result?;
    if r.finish_reason == FinishReason::Timeout {
        return Err(ApiError::for_model(ErrorCode::Timeout, &model, "generation timed out"));
    }
    let duration_ms = started.elapsed().as_millis() as u64;
    tracing::info!(
        model = %model,
        prompt_tokens = r.prompt_tokens,
        completion_tokens = r.completion_tokens,
        duration_ms,
        "chat"
    );
    Ok(Json(json!({
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": r.text },
            "finish_reason": r.finish_reason,
        }],
        "usage": {
            "prompt_tokens": r.prompt_tokens,
            "completion_tokens": r.completion_tokens,
            "total_tokens": r.prompt_tokens + r.completion_tokens,
            "duration_ms": duration_ms,
        }
    }))
    .into_response())
}

// ---------- embeddings ----------

#[derive(Deserialize)]
#[serde(untagged)]
enum Input {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct EmbedRequest {
    model: String,
    input: Input,
}

async fn embeddings(State(reg): State<AppState>, ApiJson(body): ApiJson<EmbedRequest>) -> ApiResult<Json<Value>> {
    let started = Instant::now();
    let deadline = deadline(&reg);
    reg.model_config(&body.model)?;

    let (texts, single) = match body.input {
        Input::One(t) => (vec![t], true),
        Input::Many(v) => (v, false),
    };
    if texts.is_empty() {
        return Err(ApiError::invalid("input must not be empty"));
    }
    if texts.len() > reg.cfg.limits.max_batch_size {
        return Err(ApiError::invalid(format!(
            "batch of {} is larger than max_batch_size ({})",
            texts.len(),
            reg.cfg.limits.max_batch_size
        )));
    }
    for t in &texts {
        check_text(&reg, t)?;
    }

    let result = async {
        let engine = reg.embedding(&body.model).await?;
        blocking(deadline, move || {
            let mut e = engine.lock().unwrap_or_else(PoisonError::into_inner);
            let vectors = e.embed_batch(&texts)?;
            Ok((e.dim(), vectors))
        })
        .await
    }
    .await;
    log_outcome(&reg, &body.model, started, &result);
    let (dim, vectors) = result?;

    tracing::info!(
        model = %body.model,
        count = vectors.len(),
        duration_ms = started.elapsed().as_millis() as u64,
        "embed"
    );
    let data: Vec<Value> = vectors
        .iter()
        .enumerate()
        .map(|(i, v)| json!({ "object": "embedding", "index": i, "embedding": v }))
        .collect();
    let mut out = json!({ "model": body.model, "dim": dim, "data": data });
    if single {
        out["embedding"] = json!(vectors[0]);
    } else {
        out["embeddings"] = json!(vectors);
    }
    Ok(Json(out))
}

// ---------- guard / classify ----------

#[derive(Deserialize)]
struct TextRequest {
    model: String,
    input: String,
}

struct Verdict {
    label: String,
    score: f32,
    all_scores: Vec<(String, f32)>,
    threshold: f32,
    blocked: bool,
}

async fn classify_text(
    reg: &Arc<Registry>,
    model: &str,
    text: &str,
    deadline: Instant,
) -> ApiResult<(Classification, f32)> {
    let started = Instant::now();
    check_text(reg, text)?;
    let threshold = reg.model_config(model)?.threshold.unwrap_or(0.5);
    let result = async {
        let engine = reg.classifier(model).await?;
        let text = text.to_string();
        blocking(deadline, move || {
            let mut e = engine.lock().unwrap_or_else(PoisonError::into_inner);
            e.classify(&text)
        })
        .await
    }
    .await;
    log_outcome(reg, model, started, &result);
    Ok((result?, threshold))
}

async fn run_guard(reg: &Arc<Registry>, model: &str, text: &str, deadline: Instant) -> ApiResult<Verdict> {
    let started = Instant::now();
    let (c, threshold) = classify_text(reg, model, text, deadline).await?;
    let cfg = reg.model_config(model)?;
    let safe = cfg
        .safe_labels
        .clone()
        .unwrap_or_else(|| vec!["SAFE".to_string()]);
    let uncertain = c.score < threshold;
    let blocked = if uncertain {
        cfg.block_on_uncertain.unwrap_or(true)
    } else {
        !safe.iter().any(|s| s.eq_ignore_ascii_case(&c.label))
    };
    let label = if uncertain { "UNCERTAIN".to_string() } else { c.label };
    tracing::info!(
        model,
        label = %label,
        score = f64::from(c.score),
        blocked,
        duration_ms = started.elapsed().as_millis() as u64,
        "guard"
    );
    Ok(Verdict {
        label,
        score: c.score,
        all_scores: c.all_scores,
        threshold,
        blocked,
    })
}

async fn guard(State(reg): State<AppState>, ApiJson(body): ApiJson<TextRequest>) -> ApiResult<Json<Value>> {
    reg.model_config(&body.model)?;
    let v = run_guard(&reg, &body.model, &body.input, deadline(&reg)).await?;
    Ok(Json(json!({
        "model": body.model,
        "label": v.label,
        "score": v.score,
        "all_scores": v.all_scores,
        "blocked": v.blocked,
        "threshold": v.threshold,
    })))
}

async fn classify(State(reg): State<AppState>, ApiJson(body): ApiJson<TextRequest>) -> ApiResult<Json<Value>> {
    reg.model_config(&body.model)?;
    let (c, threshold) = classify_text(&reg, &body.model, &body.input, deadline(&reg)).await?;
    // Below the threshold we do not pick a winner: the caller decides.
    let label = if c.score < threshold { "UNCERTAIN".to_string() } else { c.label };
    Ok(Json(json!({
        "model": body.model,
        "label": label,
        "score": c.score,
        "all_scores": c.all_scores,
        "threshold": threshold,
    })))
}
