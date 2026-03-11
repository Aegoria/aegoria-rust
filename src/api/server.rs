use std::sync::Arc;

use tokio::sync::RwLock;

use crate::reports::report_builder::SecurityReport;
use crate::utils::config::Config;

// shared state for axum handlers
#[derive(Clone)]
pub struct AppState {
    pub report: Arc<RwLock<Option<SecurityReport>>>,
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            report: Arc::new(RwLock::new(None)),
            config: Arc::new(config),
        }
    }
}
