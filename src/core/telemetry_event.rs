use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::log_source::LogSource;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    Authentication,
    ProcessExecution,
    NetworkConnection,
    FileAccess,
    PrivilegeEscalation,
    SystemEvent,
}

// central pipeline data type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub id: Uuid,
    pub device_id: String,
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub source: LogSource,

    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub username: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub privilege_level: Option<String>,
    pub file_path: Option<String>,
    pub network_port: Option<u16>,
    pub protocol: Option<String>,
    pub severity: Severity,
    pub mitre_technique: Option<String>,
    #[serde(default)]
    pub threat_tags: Vec<String>,

    pub raw_log: String,
}

impl TelemetryEvent {
    pub fn new(
        device_id: String,
        hostname: String,
        timestamp: DateTime<Utc>,
        event_type: EventType,
        source: LogSource,
        severity: Severity,
        raw_log: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            device_id,
            hostname,
            timestamp,
            event_type,
            source,
            process_name: None,
            process_id: None,
            username: None,
            source_ip: None,
            destination_ip: None,
            privilege_level: None,
            file_path: None,
            network_port: None,
            protocol: None,
            severity,
            mitre_technique: None,
            threat_tags: Vec::new(),
            raw_log,
        }
    }

    // lightweight json for ml model ingestion
    pub fn to_ai_json(&self) -> serde_json::Value {
        serde_json::json!({
            "timestamp": self.timestamp.to_rfc3339(),
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "process_name": self.process_name,
            "username": self.username,
            "severity": self.severity,
            "mitre_technique": self.mitre_technique,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_to_json() {
        let event = TelemetryEvent::new(
            "device-001".into(),
            "web-server-1".into(),
            Utc::now(),
            EventType::Authentication,
            LogSource::AuthLog,
            Severity::Medium,
            "Mar 10 10:00:00 web-server-1 sshd[1234]: Failed password for root".into(),
        );

        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("device-001"));
        assert!(json.contains("authentication"));
    }

    #[test]
    fn roundtrips_json() {
        let event = TelemetryEvent::new(
            "device-002".into(),
            "db-server".into(),
            Utc::now(),
            EventType::ProcessExecution,
            LogSource::Syslog,
            Severity::High,
            "suspicious binary execution".into(),
        );

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: TelemetryEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.device_id, "device-002");
        assert_eq!(deserialized.event_type, EventType::ProcessExecution);
    }

    #[test]
    fn ai_json_contains_key_fields() {
        let mut event = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::Authentication,
            LogSource::AuthLog,
            Severity::High,
            "raw".into(),
        );
        event.source_ip = Some("10.0.0.1".into());
        event.username = Some("root".into());
        event.mitre_technique = Some("T1110".into());

        let ai = event.to_ai_json();
        assert_eq!(ai["source_ip"], "10.0.0.1");
        assert_eq!(ai["username"], "root");
        assert_eq!(ai["mitre_technique"], "T1110");
        assert!(ai["timestamp"].is_string());
    }
}
