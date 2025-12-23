//! HTTP request handlers for the web API

use crate::web::api::{AnalysisRequest, WebAPIServer};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    Json as RequestJson,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// Request to delete multiple files
#[derive(Debug, Deserialize)]
pub struct DeleteFilesRequest {
    pub file_paths: Vec<String>,
}

/// Query parameters for file operations
#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub path: Option<String>,
}

/// Response for file deletion operations
#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub success: bool,
    pub results: Option<Vec<FileDeleteResult>>,
    pub message: Option<String>,
}

/// Result of deleting a single file
#[derive(Debug, Serialize)]
pub struct FileDeleteResult {
    pub file_path: String,
    pub success: bool,
}

/// Handler for starting a new analysis
pub async fn start_analysis(
    State(api_server): State<Arc<WebAPIServer>>,
    RequestJson(request): RequestJson<AnalysisRequest>,
) -> Result<Json<Value>, StatusCode> {
    match api_server.start_analysis(request).await {
        Ok(session) => Ok(Json(json!(session))),
        Err(err) => {
            tracing::error!("Failed to start analysis: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for getting analysis status
pub async fn get_analysis_status(
    State(api_server): State<Arc<WebAPIServer>>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    match api_server.get_analysis_status(&session_id).await {
        Ok(Some(session)) => Ok(Json(json!(session))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::error!("Failed to get analysis status: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for getting analysis results
pub async fn get_analysis_results(
    State(api_server): State<Arc<WebAPIServer>>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    match api_server.get_analysis_results(&session_id).await {
        Ok(Some(results)) => Ok(Json(json!(results))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::error!("Failed to get analysis results: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for getting file information
pub async fn get_file_info(
    State(api_server): State<Arc<WebAPIServer>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let file_path = params
        .get("path")
        .ok_or(StatusCode::BAD_REQUEST)?;

    match api_server.get_file_info(file_path).await {
        Ok(Some(file_info)) => Ok(Json(json!(file_info))),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::error!("Failed to get file info: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for deleting a single file
pub async fn delete_file(
    State(api_server): State<Arc<WebAPIServer>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let file_path = params
        .get("path")
        .ok_or(StatusCode::BAD_REQUEST)?;

    match api_server.delete_file(file_path).await {
        Ok(true) => Ok(Json(json!(DeleteResponse {
            success: true,
            results: None,
            message: Some("File deleted successfully".to_string()),
        }))),
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::error!("Failed to delete file: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for deleting multiple files
pub async fn delete_files(
    State(api_server): State<Arc<WebAPIServer>>,
    RequestJson(request): RequestJson<DeleteFilesRequest>,
) -> Result<Json<Value>, StatusCode> {
    match api_server.delete_files(&request.file_paths).await {
        Ok(results) => {
            let file_results: Vec<FileDeleteResult> = results
                .into_iter()
                .map(|(file_path, success)| FileDeleteResult { file_path, success })
                .collect();

            let overall_success = file_results.iter().all(|r| r.success);

            Ok(Json(json!(DeleteResponse {
                success: overall_success,
                results: Some(file_results),
                message: None,
            })))
        }
        Err(err) => {
            tracing::error!("Failed to delete files: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for cancelling an analysis
pub async fn cancel_analysis(
    State(api_server): State<Arc<WebAPIServer>>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    match api_server.cancel_analysis(&session_id).await {
        Ok(true) => Ok(Json(json!({
            "success": true,
            "message": "Analysis cancelled successfully"
        }))),
        Ok(false) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            tracing::error!("Failed to cancel analysis: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Handler for getting all active sessions
pub async fn get_active_sessions(
    State(api_server): State<Arc<WebAPIServer>>,
) -> Result<Json<Value>, StatusCode> {
    match api_server.get_active_sessions().await {
        Ok(sessions) => Ok(Json(json!(sessions))),
        Err(err) => {
            tracing::error!("Failed to get active sessions: {}", err);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
