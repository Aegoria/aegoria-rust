use anyhow::{Context, bail};

use crate::core::log_source::LogSource;
use crate::core::telemetry_event::{EventType, Severity, TelemetryEvent};
use crate::utils::time::parse_syslog_timestamp;

use super::Parser;

// auth log parser for ssh, sudo, pam events
pub struct AuthParser {
    pub device_id: String,
}

impl AuthParser {
    pub fn new(device_id: String) -> Self {
        Self { device_id }
    }
}

impl Parser for AuthParser {
    fn parse(&self, raw_line: &str) -> anyhow::Result<TelemetryEvent> {
        if raw_line.len() < 16 {
            bail!("line too short for auth log");
        }

        let timestamp_str = &raw_line[..15];
        let timestamp = parse_syslog_timestamp(timestamp_str).context("bad auth log timestamp")?;

        let remainder = &raw_line[16..];
        let mut parts = remainder.splitn(2, ' ');
        let hostname = parts.next().unwrap_or("unknown").to_string();
        let rest = parts.next().unwrap_or("");

        let (process_name, process_id, message) = parse_tag_and_message(rest);
        let auth_info = classify_auth_event(&process_name, &message);

        let mut event = TelemetryEvent::new(
            self.device_id.clone(),
            hostname,
            timestamp,
            auth_info.event_type,
            LogSource::AuthLog,
            auth_info.severity,
            raw_line.to_string(),
        );
        event.process_name = Some(process_name);
        event.process_id = process_id;
        event.username = auth_info.username;
        event.source_ip = auth_info.source_ip;
        event.privilege_level = auth_info.privilege_level;
        event.mitre_technique = auth_info.mitre_technique;
        event.network_port = auth_info.port;

        Ok(event)
    }
}

struct AuthInfo {
    event_type: EventType,
    severity: Severity,
    username: Option<String>,
    source_ip: Option<String>,
    privilege_level: Option<String>,
    mitre_technique: Option<String>,
    port: Option<u16>,
}

fn parse_tag_and_message(rest: &str) -> (String, Option<u32>, String) {
    let (tag, message) = match rest.split_once(": ") {
        Some((t, m)) => (t, m.to_string()),
        None => (rest, String::new()),
    };

    if let Some(bracket_start) = tag.find('[') {
        let process_name = tag[..bracket_start].to_string();
        let pid_str = tag[bracket_start + 1..].trim_end_matches(']');
        let process_id = pid_str.parse::<u32>().ok();
        (process_name, process_id, message)
    } else {
        (tag.to_string(), None, message)
    }
}

fn classify_auth_event(process_name: &str, message: &str) -> AuthInfo {
    let msg = message.to_lowercase();
    let pname = process_name.to_lowercase();

    // failed ssh password (T1110 brute force)
    if msg.starts_with("failed password") {
        return AuthInfo {
            event_type: EventType::Authentication,
            severity: Severity::High,
            username: extract_after(message, "for "),
            source_ip: extract_after(message, "from "),
            privilege_level: None,
            mitre_technique: Some("T1110".into()),
            port: extract_port(message),
        };
    }

    // invalid user attempt (T1078 valid accounts)
    if msg.starts_with("invalid user") {
        return AuthInfo {
            event_type: EventType::Authentication,
            severity: Severity::High,
            username: extract_after(message, "user "),
            source_ip: extract_after(message, "from "),
            privilege_level: None,
            mitre_technique: Some("T1078".into()),
            port: extract_port(message),
        };
    }

    // accepted login
    if msg.starts_with("accepted") {
        return AuthInfo {
            event_type: EventType::Authentication,
            severity: Severity::Low,
            username: extract_after(message, "for "),
            source_ip: extract_after(message, "from "),
            privilege_level: None,
            mitre_technique: None,
            port: extract_port(message),
        };
    }

    // sudo usage (T1548 abuse elevation)
    if pname == "sudo" {
        return AuthInfo {
            event_type: EventType::PrivilegeEscalation,
            severity: Severity::Medium,
            username: message.split_whitespace().next().map(String::from),
            source_ip: None,
            privilege_level: Some("root".into()),
            mitre_technique: Some("T1548".into()),
            port: None,
        };
    }

    // session opened
    if msg.contains("session opened") {
        return AuthInfo {
            event_type: EventType::Authentication,
            severity: Severity::Info,
            username: extract_after(message, "for user "),
            source_ip: None,
            privilege_level: None,
            mitre_technique: None,
            port: None,
        };
    }

    // session closed
    if msg.contains("session closed") {
        return AuthInfo {
            event_type: EventType::Authentication,
            severity: Severity::Info,
            username: extract_after(message, "for user "),
            source_ip: None,
            privilege_level: None,
            mitre_technique: None,
            port: None,
        };
    }

    // fallback
    AuthInfo {
        event_type: EventType::Authentication,
        severity: Severity::Info,
        username: None,
        source_ip: None,
        privilege_level: None,
        mitre_technique: None,
        port: None,
    }
}

// extract first word after keyword
fn extract_after(message: &str, keyword: &str) -> Option<String> {
    let lower = message.to_lowercase();
    let kw_lower = keyword.to_lowercase();
    let idx = lower.find(&kw_lower)?;
    let after = &message[idx + keyword.len()..];
    Some(after.split_whitespace().next()?.to_string())
}

// extract "port NNNN" from message
fn extract_port(message: &str) -> Option<u16> {
    let idx = message.to_lowercase().find("port ")?;
    message[idx + 5..]
        .split_whitespace()
        .next()?
        .parse::<u16>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn parser() -> AuthParser {
        AuthParser::new("test-device".into())
    }

    #[test]
    fn parses_failed_password() {
        let line = "Mar 10 10:00:00 host sshd[500]: Failed password for root from 192.168.1.100 port 22 ssh2";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.event_type, EventType::Authentication);
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.username.as_deref(), Some("root"));
        assert_eq!(event.source_ip.as_deref(), Some("192.168.1.100"));
        assert_eq!(event.network_port, Some(22));
        assert_eq!(event.mitre_technique.as_deref(), Some("T1110"));
    }

    #[test]
    fn parses_accepted_password() {
        let line = "Mar 10 10:00:00 host sshd[501]: Accepted password for admin from 10.0.0.1 port 2222 ssh2";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.severity, Severity::Low);
        assert_eq!(event.username.as_deref(), Some("admin"));
        assert_eq!(event.source_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(event.network_port, Some(2222));
    }

    #[test]
    fn parses_invalid_user() {
        let line = "Mar 10 10:00:00 host sshd[502]: Invalid user hacker from 1.2.3.4 port 22";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.username.as_deref(), Some("hacker"));
        assert_eq!(event.mitre_technique.as_deref(), Some("T1078"));
    }

    #[test]
    fn parses_sudo_command() {
        let line = "Mar 10 10:00:00 host sudo[600]: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.event_type, EventType::PrivilegeEscalation);
        assert_eq!(event.username.as_deref(), Some("admin"));
        assert_eq!(event.mitre_technique.as_deref(), Some("T1548"));
    }

    #[test]
    fn parses_session_opened() {
        let line = "Mar 10 10:00:00 host sshd[700]: pam_unix(sshd:session): session opened for user deploy";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.username.as_deref(), Some("deploy"));
    }

    #[test]
    fn rejects_short_line() {
        assert!(parser().parse("short").is_err());
    }

    #[test]
    fn parsed_auth_event_serializes() {
        let line =
            "Mar 10 10:00:00 host sshd[500]: Failed password for root from 1.2.3.4 port 22 ssh2";
        let event = parser().parse(line).unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("T1110"));
    }
}
