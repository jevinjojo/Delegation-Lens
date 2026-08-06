use std::{env, fmt, net::SocketAddr, str::FromStr};

use crate::error::AppError;

#[derive(Clone)]
pub struct Config {
    pub bind_address: SocketAddr,
    pub database_url: String,
    pub dashboard_origin: String,
    pub rpc_http_url: Option<String>,
    pub rpc_ws_url: Option<String>,
    pub chain_id: u64,
    pub confirmation_depth: u64,
    pub start_block: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, AppError> {
        let bind = env::var("API_BIND_ADDRESS")
            .or_else(|_| env::var("BIND_ADDRESS")) // fall back to the Phase 0 name
            .unwrap_or_else(|_| "127.0.0.1:8080".to_owned());

        let bind_address = SocketAddr::from_str(&bind)
            .map_err(|e| AppError::Config(format!("invalid API_BIND_ADDRESS '{bind}': {e}")))?;

        Ok(Self {
            bind_address,
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite://delegation_lens.db".to_owned()),
            dashboard_origin: env::var("DASHBOARD_ORIGIN")
                .unwrap_or_else(|_| "http://127.0.0.1:5173".to_owned()),
            rpc_http_url: env::var("RPC_HTTP_URL").ok(),
            rpc_ws_url: env::var("RPC_WS_URL").ok(),
            chain_id: parse_env("CHAIN_ID", 11_155_111)?,
            confirmation_depth: parse_env("CONFIRMATION_DEPTH", 12)?,
            start_block: parse_env("START_BLOCK", 0)?,
        })
    }
}

// Parses an env var into any FromStr type, with a typed error and a default.
fn parse_env<T>(key: &str, default: T) -> Result<T, AppError>
where
    T: FromStr,
    T::Err: fmt::Display,
{
    match env::var(key) {
        Ok(raw) => raw
            .parse::<T>()
            .map_err(|e| AppError::Config(format!("invalid {key} '{raw}': {e}"))),
        Err(_) => Ok(default),
    }
}

// RPC URLs often contain an API key. Show only scheme + host so keys never hit logs.
fn redact_url(url: &Option<String>) -> String {
    match url {
        None => "<unset>".to_owned(),
        Some(raw) => match raw.split_once("://") {
            Some((scheme, rest)) => {
                let host = rest.split('/').next().unwrap_or(rest);
                format!("{scheme}://{host}/***redacted***")
            }
            None => "***redacted***".to_owned(),
        },
    }
}

// Manual Debug so logging the config NEVER prints raw RPC secrets.
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_address", &self.bind_address)
            .field("database_url", &self.database_url)
            .field("dashboard_origin", &self.dashboard_origin)
            .field("rpc_http_url", &redact_url(&self.rpc_http_url))
            .field("rpc_ws_url", &redact_url(&self.rpc_ws_url))
            .field("chain_id", &self.chain_id)
            .field("confirmation_depth", &self.confirmation_depth)
            .field("start_block", &self.start_block)
            .finish()
    }
}
