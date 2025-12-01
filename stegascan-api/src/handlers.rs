use axum::{extract::Multipart, response::Json};
use serde_json::json;

use crate::analysis::run_full_analysis;
use crate::error::ApiError;
use crate::models::AnalysisResponse;

pub async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "service": "Stegascan API",
        "version": "0.1.0",
        "description": "Steganography detection and analysis API",
        "endpoint": "POST /api/scan"
    }))
}

pub async fn scan_file(mut multipart: Multipart) -> Result<Json<AnalysisResponse>, ApiError> {
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut video_sample_rate: usize = 30;

    // Parse multipart form data
    while let Some(field) = multipart.next_field().await? {
        let field_name = field.name().unwrap_or("").to_string();

        match field_name.as_str() {
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                file_data = Some(field.bytes().await?.to_vec());
            }
            "video_sample_rate" => {
                if let Ok(text) = field.text().await {
                    video_sample_rate = text.parse().unwrap_or(30);
                }
            }
            _ => {}
        }
    }

    let file_data = file_data.ok_or(ApiError::MissingFile)?;
    let filename = filename.unwrap_or_else(|| "unknown".to_string());

    tracing::info!("Scanning file: {} ({} bytes)", filename, file_data.len());

    // Create temporary file
    let temp_file = tempfile::NamedTempFile::new()?;
    std::fs::write(temp_file.path(), &file_data)?;

    // Run analysis synchronously
    let result =
        run_full_analysis(&temp_file.path().to_path_buf(), video_sample_rate, false).await?;

    tracing::info!("Analysis completed for: {}", filename);

    Ok(Json(result))
}
