use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initializes structured logging for the whole app.
/// The level is controlled by the RUST_LOG env var; if unset we default to
/// `info` globally and `debug` for our own crate.
pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,delegation_lens=debug"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

/// Installs the global Prometheus recorder and seeds/describes all metrics so
/// they appear at zero before the first real event. Call once at startup.
pub fn init_metrics() -> PrometheusHandle {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("install prometheus recorder");

    describe_counter!(
        "blocks_processed_total",
        "Blocks applied to the canonical chain"
    );
    describe_counter!(
        "authorizations_detected_total",
        "EIP-7702 authorizations decoded"
    );
    describe_counter!("reorgs_total", "Blocks reverted due to reorgs");
    describe_counter!("rpc_errors_total", "Failed RPC attempts");
    describe_counter!(
        "implementations_analyzed_total",
        "Implementations run through the analyzer"
    );
    describe_counter!("findings_total", "Security findings produced");
    describe_gauge!("active_delegations", "Accounts with an active delegation");
    describe_gauge!("ingestion_lag_blocks", "Blocks behind chain head");
    describe_gauge!("sse_clients", "Connected SSE clients");
    describe_histogram!(
        "block_processing_duration_seconds",
        "Time to process a block"
    );
    describe_histogram!(
        "analysis_duration_seconds",
        "Time to analyze an implementation"
    );

    counter!("blocks_processed_total").increment(0);
    counter!("authorizations_detected_total").increment(0);
    counter!("reorgs_total").increment(0);
    counter!("rpc_errors_total").increment(0);
    counter!("implementations_analyzed_total").increment(0);
    counter!("findings_total").increment(0);
    gauge!("active_delegations").set(0.0);
    gauge!("ingestion_lag_blocks").set(0.0);
    gauge!("sse_clients").set(0.0);

    handle
}

/// A non-global handle for tests (avoids "recorder already installed" panics).
#[cfg(test)]
pub fn test_metrics_handle() -> PrometheusHandle {
    PrometheusBuilder::new().build_recorder().handle()
}
