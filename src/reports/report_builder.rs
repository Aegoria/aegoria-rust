use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::analyzer::AnalysisResult;
use crate::analyzer::timeline::AttackTimeline;
use crate::core::risk_score::{RiskLevel, RiskScore};
use crate::core::telemetry_event::TelemetryEvent;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SystemHealth {
    Healthy,
    Warning,
    Critical,
}

// security assessment report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub timestamp: DateTime<Utc>,
    pub system_health: SystemHealth,
    pub events_processed: usize,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub detected_threats: DetectedThreats,
    pub correlation_findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub attack_timeline: AttackTimeline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedThreats {
    pub failed_login_bursts: u32,
    pub privilege_escalations: u32,
    pub suspicious_processes: Vec<String>,
    pub network_anomalies: Vec<String>,
}

impl SecurityReport {
    pub fn build(
        risk: &RiskScore,
        analysis: &AnalysisResult,
        events: &[TelemetryEvent],
        recommendations: Vec<String>,
    ) -> Self {
        let system_health = match risk.level {
            RiskLevel::Low => SystemHealth::Healthy,
            RiskLevel::Medium => SystemHealth::Warning,
            RiskLevel::High | RiskLevel::Critical => SystemHealth::Critical,
        };

        let attack_timeline = AttackTimeline::build(events);

        Self {
            timestamp: Utc::now(),
            system_health,
            events_processed: events.len(),
            risk_score: risk.total_score,
            risk_level: risk.level.clone(),
            detected_threats: DetectedThreats {
                failed_login_bursts: analysis.failed_logins,
                privilege_escalations: analysis.privilege_escalations,
                suspicious_processes: analysis.suspicious_processes.clone(),
                network_anomalies: analysis.network_anomalies.clone(),
            },
            correlation_findings: analysis.correlation_findings.clone(),
            recommendations,
            attack_timeline,
        }
    }
}
