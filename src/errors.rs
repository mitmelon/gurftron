//! One error shape for the whole API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    ModelNotFound,
    ModelNotReady,
    ModelLoadFailed,
    InvalidRequest,
    PromptTooLong,
    GuardBlocked,
    Timeout,
    InternalError,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::ModelNotFound => "MODEL_NOT_FOUND",
            ErrorCode::ModelNotReady => "MODEL_NOT_READY",
            ErrorCode::ModelLoadFailed => "MODEL_LOAD_FAILED",
            ErrorCode::InvalidRequest => "INVALID_REQUEST",
            ErrorCode::PromptTooLong => "PROMPT_TOO_LONG",
            ErrorCode::GuardBlocked => "GUARD_BLOCKED",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::InternalError => "INTERNAL_ERROR",
        }
    }

    pub fn status(self) -> StatusCode {
        match self {
            ErrorCode::ModelNotFound => StatusCode::NOT_FOUND,
            ErrorCode::ModelNotReady => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ModelLoadFailed => StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::PromptTooLong => StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::GuardBlocked => StatusCode::FORBIDDEN,
            ErrorCode::Timeout => StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    pub model: Option<String>,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            model: None,
        }
    }

    pub fn for_model(code: ErrorCode, model: &str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            model: Some(model.to_string()),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::InvalidRequest, message)
    }

    pub fn internal(message: impl std::fmt::Display) -> Self {
        Self::new(ErrorCode::InternalError, message.to_string())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": {
                "code": self.code.as_str(),
                "message": self.message,
                "model": self.model,
            }
        });
        (self.code.status(), Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
