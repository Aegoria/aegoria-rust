pub mod anomaly_patterns;
pub mod behavior_engine;
pub mod correlation;
pub mod timeline;

use serde::{Deserialize, Serialize};

use crate::core::telemetry_event::TelemetryEvent;

// behavioral analysis output
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub failed_logins: u32,
    pub privilege_escalations: u32,
    pub suspicious_processes: Vec<String>,
    pub network_anomalies: Vec<String>,
    pub correlation_findings: Vec<String>,
}

// analysis engine trait
pub trait Analyzer {
    fn analyze(&self, events: &[TelemetryEvent]) -> AnalysisResult;
}
