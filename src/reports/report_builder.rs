use std::collections::HashMap;

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
    pub pipeline_metrics: PipelineMetrics,
    pub event_distribution: HashMap<String, usize>,
    pub threat_tags_summary: Vec<String>,
    pub detected_threats: DetectedThreats,
    pub correlation_findings: Vec<String>,
    pub recommendations: Vec<String>,
    pub attack_timeline: AttackTimeline,
}

// pipeline performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineMetrics {
    pub events_per_second: f64,
    pub pipeline_latency_ms: u128,
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
        Self::build_with_latency(risk, analysis, events, recommendations, 0)
    }

    // build report with pipeline latency measurement
    pub fn build_with_latency(
        risk: &RiskScore,
        analysis: &AnalysisResult,
        events: &[TelemetryEvent],
        recommendations: Vec<String>,
        pipeline_latency_ms: u128,
    ) -> Self {
        let system_health = match risk.level {
            RiskLevel::Low => SystemHealth::Healthy,
            RiskLevel::Medium => SystemHealth::Warning,
            RiskLevel::High | RiskLevel::Critical => SystemHealth::Critical,
        };

        let attack_timeline = AttackTimeline::build(events);

        // compute event type distribution
        let mut event_distribution: HashMap<String, usize> = HashMap::new();
        for event in events {
            let key = format!("{:?}", event.event_type).to_lowercase();
            *event_distribution.entry(key).or_default() += 1;
        }

        // aggregate unique threat tags
        let mut threat_tags_summary: Vec<String> = events
            .iter()
            .flat_map(|e| e.threat_tags.iter().cloned())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        threat_tags_summary.sort();

        // events per second (avoid div by zero)
        let eps = if pipeline_latency_ms > 0 {
            events.len() as f64 / (pipeline_latency_ms as f64 / 1000.0)
        } else {
            0.0
        };

        Self {
            timestamp: Utc::now(),
            system_health,
            events_processed: events.len(),
            risk_score: risk.total_score,
            risk_level: risk.level.clone(),
            pipeline_metrics: PipelineMetrics {
                events_per_second: eps,
                pipeline_latency_ms,
            },
            event_distribution,
            threat_tags_summary,
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
