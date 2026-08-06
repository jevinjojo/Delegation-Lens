use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid request: {0}")]
    Validation(String),

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("unsupported transaction: {0}")]
    UnsupportedTransaction(String),

    #[error("invalid authorization: {0}")]
    InvalidAuthorization(String),

    #[error("reorg error: {0}")]
    Reorg(String),

    #[error("analysis error: {0}")]
    Analysis(String),

    #[error("missing code for address: {0}")]
    MissingCode(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            // Client errors: safe to return the message to the caller.
            Self::Validation(m)
            | Self::UnsupportedTransaction(m)
            | Self::InvalidAuthorization(m) => (StatusCode::BAD_REQUEST, m),

            Self::NotFound(m) => (StatusCode::NOT_FOUND, m),

            // Server errors: log the detail, return a generic message (no leaks).
            Self::Database(error) => {
                tracing::error!(%error, "database operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "database operation failed".to_owned(),
                )
            }
            Self::Rpc(m)
            | Self::Reorg(m)
            | Self::Analysis(m)
            | Self::MissingCode(m)
            | Self::Config(m)
            | Self::Internal(m) => {
                tracing::error!(detail = %m, "internal application error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_owned(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
