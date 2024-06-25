use axum::http::StatusCode;
use axum::response::Json;
use axum::response::{IntoResponse, Response};
use jwt_simple::reexports::serde_json::json;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorOutput {
    pub error: String,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("io error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("jwt error: {0}")]
    JWTError(#[from] jwt_simple::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response<axum::body::Body> {
        let status = match self {
            AppError::JWTError(_) => StatusCode::FORBIDDEN,
            AppError::IOError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (
            status,
            Json(json!({
                "error": self.to_string(),
            })),
        )
            .into_response()
    }
}
