use axum::{
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Missing file in request")]
    MissingFile,

    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Multipart error: {0}")]
    Multipart(#[from] axum::extract::multipart::MultipartError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::MissingFile => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiError::AnalysisFailed(_) => (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()),
            ApiError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ApiError::Multipart(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}
