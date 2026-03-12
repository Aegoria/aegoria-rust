use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::core::telemetry_event::{EventType, Severity, TelemetryEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub description: String,
    pub severity: Severity,
    pub source_ip: Option<String>,
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTimeline {
    pub events: Vec<TimelineEvent>,
}

impl AttackTimeline {
    // build chronological timeline from telemetry events
    pub fn build(events: &[TelemetryEvent]) -> Self {
        let mut timeline_events: Vec<TimelineEvent> = events
            .iter()
            .filter(|e| e.severity != Severity::Info)
            .map(|e| TimelineEvent {
                timestamp: e.timestamp,
                event_type: format!("{:?}", e.event_type).to_lowercase(),
                description: describe_event(e),
                severity: e.severity.clone(),
                source_ip: e.source_ip.clone(),
                username: e.username.clone(),
            })
            .collect();

        timeline_events.sort_by_key(|e| e.timestamp);

        Self {
            events: timeline_events,
        }
    }
}

fn describe_event(event: &TelemetryEvent) -> String {
    let process = event.process_name.as_deref().unwrap_or("unknown");

    match event.event_type {
        EventType::Authentication => {
            let user = event.username.as_deref().unwrap_or("unknown");
            let ip = event.source_ip.as_deref().unwrap_or("local");
            if event.severity == Severity::High || event.severity == Severity::Critical {
                format!("failed login attempt by {} from {}", user, ip)
            } else {
                format!("successful login by {} from {}", user, ip)
            }
        }
        EventType::PrivilegeEscalation => {
            let user = event.username.as_deref().unwrap_or("unknown");
            format!("privilege escalation by {}", user)
        }
        EventType::ProcessExecution => {
            format!("{} process started", process)
        }
        EventType::NetworkConnection => {
            let ip = event.source_ip.as_deref().unwrap_or("unknown");
            let port = event
                .network_port
                .map(|p| format!(" port {}", p))
                .unwrap_or_default();
            format!("network connection from {}{}", ip, port)
        }
        EventType::FileAccess => {
            let path = event.file_path.as_deref().unwrap_or("unknown");
            format!("file access: {}", path)
        }
        EventType::SystemEvent => {
            format!("{}: system event", process)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::log_source::LogSource;

    #[test]
    fn builds_sorted_timeline() {
        let earlier = Utc::now() - chrono::Duration::minutes(5);
        let later = Utc::now();

        let mut e1 = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            later,
            EventType::PrivilegeEscalation,
            LogSource::AuthLog,
            Severity::Medium,
            "raw".into(),
        );
        e1.username = Some("admin".into());

        let mut e2 = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            earlier,
            EventType::Authentication,
            LogSource::AuthLog,
            Severity::High,
            "raw".into(),
        );
        e2.username = Some("root".into());
        e2.source_ip = Some("10.0.0.1".into());

        let timeline = AttackTimeline::build(&[e1, e2]);
        assert_eq!(timeline.events.len(), 2);
        // earlier event first
        assert!(timeline.events[0].timestamp < timeline.events[1].timestamp);
        assert!(timeline.events[0].description.contains("failed login"));
        assert!(timeline.events[1].description.contains("escalation"));
    }

    #[test]
    fn filters_info_severity() {
        let event = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::SystemEvent,
            LogSource::Syslog,
            Severity::Info,
            "raw".into(),
        );
        let timeline = AttackTimeline::build(&[event]);
        assert!(timeline.events.is_empty());
    }
}
