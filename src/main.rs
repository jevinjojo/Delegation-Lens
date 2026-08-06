#![allow(dead_code)]

mod analyzer;
mod api;
mod bench;
mod chain;
mod config;
mod domain;
mod error;
mod policy;
mod source;
mod storage;
mod telemetry;
mod tracker;

use tokio::sync::broadcast;

use crate::{
    api::AppState,
    config::Config,
    error::AppError,
    source::{decode_transaction, validate_transaction, InspectionReport, TxFixture},
    storage::Storage,
};

#[tokio::main]
async fn main() -> Result<(), AppError> {
    let _ = dotenvy::dotenv();
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("inspect-file") => {
            let path = args
                .get(2)
                .ok_or_else(|| AppError::Validation("usage: inspect-file <path>".into()))?;
            let json = std::fs::read_to_string(path)
                .map_err(|e| AppError::Internal(format!("read {path}: {e}")))?;
            inspect(&json)
        }
        Some("inspect-tx-json") => {
            let json = args
                .get(2)
                .ok_or_else(|| AppError::Validation("usage: inspect-tx-json '<json>'".into()))?;
            inspect(json)
        }
        Some("gen-fixtures") => source::generate_fixtures(),
        Some("bench") => bench::run().await,
        _ => serve().await,
    }
}

/// Decode + validate a single transaction JSON and print deterministic output.
fn inspect(json: &str) -> Result<(), AppError> {
    let chain_id = Config::from_env()?.chain_id;
    let tx: TxFixture = serde_json::from_str(json)
        .map_err(|e| AppError::Validation(format!("invalid fixture json: {e}")))?;
    let decoded = decode_transaction(&tx)?;
    let issues = validate_transaction(&decoded, chain_id);
    let report = InspectionReport { decoded, issues };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| AppError::Internal(e.to_string()))?
    );
    Ok(())
}

async fn serve() -> Result<(), AppError> {
    telemetry::init();
    let metrics = telemetry::init_metrics();

    let config = Config::from_env()?;
    tracing::info!(?config, "starting delegation-lens");

    let storage = Storage::connect(&config.database_url).await?;
    let (events, _rx) = broadcast::channel(256);
    let state = AppState {
        storage,
        events,
        metrics: metrics.clone(),
    };

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Ingestion (background), with shutdown signal.
    if let Some(http_url) = config.rpc_http_url.clone() {
        let pool = state.storage.pool().clone();
        let ev = state.events.clone();
        let ws_url = config.rpc_ws_url.clone();
        let chain_id = config.chain_id;
        let start_block = config.start_block;
        let rx = shutdown_rx.clone();
        tokio::spawn(async move {
            if let Err(error) =
                source::run_ingestion(pool, ev, http_url, ws_url, chain_id, start_block, rx).await
            {
                tracing::error!(%error, "ingestion task exited");
            }
        });
    }

    // Metrics upkeep (histogram maintenance / idle cleanup).
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            metrics.run_upkeep();
        }
    });

    let app = api::build_router(state, &config.dashboard_origin)?;
    let listener = tokio::net::TcpListener::bind(config.bind_address)
        .await
        .map_err(|e| AppError::Internal(format!("failed to bind {}: {e}", config.bind_address)))?;
    tracing::info!("listening on http://{}", config.bind_address);

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received; draining");
            let _ = shutdown_tx.send(true);
        })
        .await
        .map_err(|e| AppError::Internal(format!("server error: {e}")))?;

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received, stopping");
}
