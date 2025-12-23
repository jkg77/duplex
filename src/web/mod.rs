//! Web interface components for the duplicate file analyzer

pub mod api;
pub mod handlers;
pub mod websocket;

pub use api::WebAPIServer;

use axum::{
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, services::ServeDir};

/// Create the web application router
pub fn create_app() -> Router {
    let api_server = Arc::new(WebAPIServer::new());

    Router::new()
        // Analysis endpoints
        .route("/api/analysis", post(handlers::start_analysis))
        .route("/api/analysis/:id", get(handlers::get_analysis_status))
        .route("/api/analysis/:id/cancel", post(handlers::cancel_analysis))
        .route(
            "/api/analysis/:id/results",
            get(handlers::get_analysis_results),
        )
        .route("/api/sessions", get(handlers::get_active_sessions))
        
        // File endpoints
        .route("/api/files", get(handlers::get_file_info))
        .route("/api/files", axum::routing::delete(handlers::delete_file))
        .route("/api/files/batch", axum::routing::delete(handlers::delete_files))
        
        // WebSocket route
        .route("/ws", get(websocket::websocket_handler))
        
        // Static file serving
        .nest_service("/", ServeDir::new("web/static"))
        
        // Add shared state
        .with_state(api_server)
        
        // CORS middleware
        .layer(CorsLayer::permissive())
}

/// Start the web server
pub async fn start_server(host: &str, port: u16) -> crate::Result<()> {
    let app = create_app();
    let addr = format!("{}:{}", host, port);

    tracing::info!("Starting web server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
