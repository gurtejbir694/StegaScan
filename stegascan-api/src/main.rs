use axum::{
    Router,
    routing::{get, post},
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod analysis;
mod error;
mod handlers;
mod models;

use handlers::*;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "stegascan_api=debug,tower_http=debug,axum=trace".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Build routes
    let app = Router::new()
        .route("/", get(root))
        .route("/api/scan", post(scan_file))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::info!("🚀 Stegascan API Server");
    tracing::info!("📖 Endpoint: POST /api/scan - Upload file and get analysis");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::warn!("Port 3000 in use, trying port 3001...");
            let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
            tokio::net::TcpListener::bind(addr).await.unwrap_or_else(|e| {
                panic!("Failed to bind to port 3001: {}. Please free up ports 3000-3001 or specify PORT env var", e);
            })
        }
        Err(e) => panic!("Failed to bind to port: {}", e),
    };

    tracing::info!("✅ Server ready on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}
