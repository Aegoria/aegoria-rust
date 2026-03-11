use tracing::info;

use crate::core::telemetry_event::TelemetryEvent;

use super::{AnalysisResult, Analyzer, anomaly_patterns, correlation};

pub struct BehaviorEngine;

impl Analyzer for BehaviorEngine {
    fn analyze(&self, events: &[TelemetryEvent]) -> AnalysisResult {
        info!("analyzing {} telemetry events", events.len());

        let failed_logins = anomaly_patterns::detect_failed_login_burst(events);
        let privilege_escalations = anomaly_patterns::detect_privilege_escalation(events);
        let suspicious_processes = anomaly_patterns::detect_suspicious_processes(events);
        let network_anomalies = anomaly_patterns::detect_network_anomalies(events);

        // event correlation
        let mut correlation_findings = Vec::new();
        correlation_findings.extend(correlation::correlate_login_then_escalation(events));
        correlation_findings.extend(correlation::correlate_login_then_recon(events));
        correlation_findings.extend(correlation::correlate_connections_and_suspicious_port(
            events,
        ));

        info!(
            "analysis: {} bursts, {} escalations, {} procs, {} net, {} correlations",
            failed_logins,
            privilege_escalations,
            suspicious_processes.len(),
            network_anomalies.len(),
            correlation_findings.len(),
        );

        AnalysisResult {
            failed_logins,
            privilege_escalations,
            suspicious_processes,
            network_anomalies,
            correlation_findings,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::log_source::LogSource;
    use crate::core::telemetry_event::{EventType, Severity};
    use chrono::Utc;

    #[test]
    fn empty_events_produce_empty_result() {
        let result = BehaviorEngine.analyze(&[]);
        assert_eq!(result.failed_logins, 0);
        assert_eq!(result.privilege_escalations, 0);
        assert!(result.suspicious_processes.is_empty());
        assert!(result.network_anomalies.is_empty());
        assert!(result.correlation_findings.is_empty());
    }

    #[test]
    fn mixed_events_produce_correct_counts() {
        let mut events = Vec::new();

        // 6 failed logins from same ip → 1 burst
        for _ in 0..6 {
            let mut e = TelemetryEvent::new(
                "d".into(),
                "h".into(),
                Utc::now(),
                EventType::Authentication,
                LogSource::AuthLog,
                Severity::High,
                "raw".into(),
            );
            e.source_ip = Some("10.0.0.1".into());
            events.push(e);
        }

        // 2 privilege escalations
        for _ in 0..2 {
            events.push(TelemetryEvent::new(
                "d".into(),
                "h".into(),
                Utc::now(),
                EventType::PrivilegeEscalation,
                LogSource::AuthLog,
                Severity::Medium,
                "raw".into(),
            ));
        }

        // 1 suspicious process
        let mut nmap = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::ProcessExecution,
            LogSource::Syslog,
            Severity::High,
            "raw".into(),
        );
        nmap.process_name = Some("nmap".into());
        events.push(nmap);

        let result = BehaviorEngine.analyze(&events);
        assert_eq!(result.failed_logins, 1);
        assert_eq!(result.privilege_escalations, 2);
        assert_eq!(result.suspicious_processes, vec!["nmap"]);
    }

    #[test]
    fn produces_correlation_findings() {
        let mut fail = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::Authentication,
            LogSource::AuthLog,
            Severity::High,
            "raw".into(),
        );
        fail.username = Some("root".into());

        let mut esc = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::PrivilegeEscalation,
            LogSource::AuthLog,
            Severity::Medium,
            "raw".into(),
        );
        esc.username = Some("root".into());

        let result = BehaviorEngine.analyze(&[fail, esc]);
        assert!(!result.correlation_findings.is_empty());
        assert!(result.correlation_findings[0].contains("root"));
    }
}
