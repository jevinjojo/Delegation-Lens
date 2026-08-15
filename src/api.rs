use axum::{
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::get,
    Json, Router,
};
use futures_core::Stream;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    domain::{CreateDelegation, Delegation, DelegationCreatedEvent},
    error::AppError,
    storage::{AccountDelegation, AlertRow, HistoryRow, ImplementationSummary, Stats, Storage},
};

// Shared application state. Cloned into every request handler.

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub events: broadcast::Sender<DelegationCreatedEvent>,
    pub metrics: PrometheusHandle,
}

// Builds the full router with routes, CORS, and tracing.
pub fn build_router(state: AppState, dashboard_origin: &str) -> Result<Router, AppError> {
    let origin = dashboard_origin
        .parse::<axum::http::HeaderValue>()
        .map_err(|e| AppError::Config(format!("invalid dashboard origin: {e}")))?;
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE]);

    // 60 requests/minute per key on expensive endpoints.
    let limiter = RateLimiter::new(60, Duration::from_secs(60));

    let expensive = Router::new()
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/accounts/{address}/history", get(account_history))
        .route("/api/v1/implementations/{address}", get(implementation))
        .route(
            "/api/v1/implementations/{address}/findings",
            get(implementation_findings),
        )
        .layer(middleware::from_fn_with_state(limiter, rate_limit))
        .with_state(state.clone());

    let base = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/api/v1/openapi.yaml", get(openapi))
        .route(
            "/api/v1/delegations",
            get(list_delegations).post(create_delegation),
        )
        .route("/api/v1/events", get(events))
        .route(
            "/api/v1/accounts/{address}/delegation",
            get(account_delegation),
        )
        .route("/api/v1/transactions/{hash}", get(transaction))
        .route("/api/v1/alerts", get(alerts))
        // routes (add to base):
        .route("/api/v1/changes", get(changes))
        .route("/api/v1/reorgs", get(reorgs))
        .with_state(state);

    Ok(base
        .merge(expensive)
        .layer(cors)
        .layer(TraceLayer::new_for_http()))
}

// ───────────────────────── Pagination ─────────────────────────

#[derive(Debug, Deserialize)]
struct Pagination {
    limit: Option<i64>,
    cursor: Option<i64>,
}

#[derive(serde::Serialize)]
struct Page<T: serde::Serialize> {
    items: Vec<T>,
    next_cursor: Option<i64>,
    limit: i64,
}

fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(50).clamp(1, 200)
}

// ───────────────────────── Validation ─────────────────────────

fn validate_address(a: &str) -> Result<String, AppError> {
    if a.len() == 42 && a.starts_with("0x") && a[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(a.to_ascii_lowercase())
    } else {
        Err(AppError::Validation(format!("invalid address: {a}")))
    }
}

fn validate_tx_hash(h: &str) -> Result<String, AppError> {
    if h.len() == 66 && h.starts_with("0x") && h[2..].bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(h.to_ascii_lowercase())
    } else {
        Err(AppError::Validation(format!(
            "invalid transaction hash: {h}"
        )))
    }
}

// ───────────────────────── Handlers ─────────────────────────

async fn account_delegation(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<AccountDelegation>, AppError> {
    let addr = validate_address(&address)?;
    state
        .storage
        .account_delegation(&addr)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound(format!("no delegation for {addr}")))
}

async fn account_history(
    State(state): State<AppState>,
    Path(address): Path<String>,
    Query(page): Query<Pagination>,
) -> Result<Json<Page<HistoryRow>>, AppError> {
    let addr = validate_address(&address)?;
    let limit = clamp_limit(page.limit);
    let cursor = page.cursor.unwrap_or(i64::MAX);
    let items = state.storage.account_history(&addr, limit, cursor).await?;
    let next_cursor = (items.len() as i64 == limit)
        .then(|| items.last().map(|r| r.rowid))
        .flatten();
    Ok(Json(Page {
        items,
        next_cursor,
        limit,
    }))
}

async fn implementation(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<ImplementationSummary>, AppError> {
    let addr = validate_address(&address)?;
    state
        .storage
        .implementation_summary(&addr)
        .await?
        .map(Json)
        .ok_or_else(|| AppError::NotFound(format!("unknown implementation {addr}")))
}

async fn implementation_findings(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let addr = validate_address(&address)?;
    let findings = state.storage.findings_for(&addr).await?;
    Ok(Json(
        json!({ "implementation": addr, "findings": findings }),
    ))
}

async fn transaction(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<Vec<HistoryRow>>, AppError> {
    let tx = validate_tx_hash(&hash)?;
    let changes = state.storage.transaction_changes(&tx).await?;
    if changes.is_empty() {
        return Err(AppError::NotFound(format!(
            "no delegation changes for tx {tx}"
        )));
    }
    Ok(Json(changes))
}

async fn changes(
    State(state): State<AppState>,
    Query(page): Query<Pagination>,
) -> Result<Json<Page<HistoryRow>>, AppError> {
    let limit = clamp_limit(page.limit);
    let cursor = page.cursor.unwrap_or(i64::MAX);
    let items = state.storage.recent_changes(limit, cursor).await?;
    let next_cursor = (items.len() as i64 == limit)
        .then(|| items.last().map(|r| r.rowid))
        .flatten();
    Ok(Json(Page {
        items,
        next_cursor,
        limit,
    }))
}

async fn reorgs(
    State(state): State<AppState>,
    Query(page): Query<Pagination>,
) -> Result<Json<Vec<crate::storage::ReorgEvent>>, AppError> {
    Ok(Json(
        state.storage.recent_reorgs(clamp_limit(page.limit)).await?,
    ))
}

async fn alerts(State(state): State<AppState>) -> Result<Json<Vec<AlertRow>>, AppError> {
    Ok(Json(state.storage.alerts(100).await?))
}

async fn stats(State(state): State<AppState>) -> Result<Json<Stats>, AppError> {
    Ok(Json(state.storage.stats().await?))
}

async fn openapi() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/yaml")],
        include_str!("../docs/openapi.yaml"),
    )
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    // Pull-model gauge: refresh from the DB right before rendering.
    if let Ok(s) = state.storage.stats().await {
        metrics::gauge!("active_delegations").set(s.active_delegations as f64);
    }
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        state.metrics.render(),
    )
}

/// Increments the SSE client gauge for the lifetime of a connection.
struct ClientGuard;
impl ClientGuard {
    fn new() -> Self {
        metrics::gauge!("sse_clients").increment(1.0);
        Self
    }
}
impl Drop for ClientGuard {
    fn drop(&mut self) {
        metrics::gauge!("sse_clients").decrement(1.0);
    }
}

// ───────────────────────── Rate limiting ─────────────────────────

#[derive(Clone)]
struct RateLimiter {
    state: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    max: u32,
    window: Duration,
}

impl RateLimiter {
    fn new(max: u32, window: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max,
            window,
        }
    }
    fn allow(&self, key: &str) -> bool {
        let mut map = self.state.lock().expect("rate limiter mutex");
        let now = Instant::now();
        let entry = map.entry(key.to_owned()).or_insert((0, now));
        if now.duration_since(entry.1) > self.window {
            *entry = (0, now); // new window
        }
        entry.0 += 1;
        entry.0 <= self.max
    }
}

async fn rate_limit(
    State(limiter): State<RateLimiter>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    // Key by forwarded client IP if present; production would use a real peer addr / API key.
    let key = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("global")
        .to_owned();

    if limiter.allow(&key) {
        next.run(request).await
    } else {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "rate limit exceeded" })),
        )
            .into_response()
    }
}

// Liveness: is the process up? No DB check needed.
async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

// Readiness: can we actually serve traffic (is the DB reachable)?
async fn ready(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    state.storage.is_ready().await?;
    Ok(Json(json!({ "status": "ready" })))
}

// POST /api/v1/delegations
async fn create_delegation(
    State(state): State<AppState>,
    Json(payload): Json<CreateDelegation>,
) -> Result<impl IntoResponse, AppError> {
    // 1. Turn the (possibly empty) request into a full domain object with defaults.
    let delegation = payload.into_delegation();

    // 2. PERSIST FIRST — this ordering is a Phase 0 exit criterion.
    let stored = state.storage.insert(&delegation).await?;

    // 3. THEN broadcast. If no SSE clients are connected, send() returns Err —
    //    that's fine and expected, so we deliberately ignore it.
    let event = DelegationCreatedEvent {
        kind: "delegation.created",
        delegation: stored.clone(),
    };
    let _ = state.events.send(event);

    // 4. 201 Created with the stored record.
    Ok((StatusCode::CREATED, Json(stored)))
}

// GET /api/v1/delegations
async fn list_delegations(
    State(state): State<AppState>,
) -> Result<Json<Vec<Delegation>>, AppError> {
    let rows = state.storage.list().await?;
    Ok(Json(rows))
}

// GET /api/v1/events  — Server-Sent Events stream
async fn events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut receiver = state.events.subscribe();
    let guard = ClientGuard::new();

    let stream = async_stream::stream! {
        let _guard = guard; // dropped when the client disconnects -> gauge decrements
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_owned());
                    yield Ok(Event::default().event("delegation").data(data));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracker;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt; // for `oneshot`

    async fn test_state() -> AppState {
        let storage = Storage::in_memory().await.expect("storage");
        let (events, _rx) = broadcast::channel(16);
        AppState {
            storage,
            events,
            metrics: crate::telemetry::test_metrics_handle(),
        }
    }

    fn get_req(uri: &str) -> Request<Body> {
        Request::builder().uri(uri).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn create_then_list_returns_one() {
        let app = build_router(test_state().await, "http://127.0.0.1:5173").expect("router");

        // POST an empty body -> defaults fill in -> 201 Created
        let created = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/delegations")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::CREATED);

        // GET the list -> 200 OK
        let listed = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/delegations")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(listed.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_invalid_address() {
        let app = build_router(test_state().await, "http://127.0.0.1:5173").unwrap();
        let res = app
            .oneshot(get_req("/api/v1/accounts/not-an-address/delegation"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn stats_and_account_reflect_tracker() {
        let state = test_state().await;
        let auth = "0x00000000000000000000000000000000000000aa";
        tracker::apply_block(
            state.storage.pool(),
            &tracker::BlockInput {
                number: 1,
                hash: "h1".into(),
                parent_hash: "GENESIS".into(),
                timestamp: 1,
                changes: vec![tracker::ChangeInput {
                    authority: auth.into(),
                    new_implementation: Some("0x00000000000000000000000000000000000000bb".into()),
                    tx_hash: "0xtx".into(),
                    nonce: None,
                }],
            },
        )
        .await
        .unwrap();

        let app = build_router(state, "http://127.0.0.1:5173").unwrap();

        let stats = app.clone().oneshot(get_req("/api/v1/stats")).await.unwrap();
        assert_eq!(stats.status(), StatusCode::OK);

        let found = app
            .clone()
            .oneshot(get_req(&format!("/api/v1/accounts/{auth}/delegation")))
            .await
            .unwrap();
        assert_eq!(found.status(), StatusCode::OK);

        let missing = app
            .oneshot(get_req(
                "/api/v1/accounts/0x00000000000000000000000000000000000000cc/delegation",
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }
}
