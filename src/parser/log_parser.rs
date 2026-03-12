use anyhow::{Context, bail};

use crate::core::log_source::LogSource;
use crate::core::telemetry_event::{EventType, Severity, TelemetryEvent};
use crate::utils::time::parse_syslog_timestamp;

use super::Parser;

// generic syslog parser
// format: "Mon DD HH:MM:SS hostname process[pid]: message"
pub struct LogParser {
    pub device_id: String,
}

impl LogParser {
    pub fn new(device_id: String) -> Self {
        Self { device_id }
    }
}

impl Parser for LogParser {
    fn parse(&self, raw_line: &str) -> anyhow::Result<TelemetryEvent> {
        if raw_line.len() < 16 {
            bail!("line too short for syslog");
        }

        let timestamp_str = &raw_line[..15];
        let timestamp = parse_syslog_timestamp(timestamp_str).context("bad syslog timestamp")?;

        let remainder = &raw_line[16..];
        let mut parts = remainder.splitn(2, ' ');
        let hostname = parts.next().unwrap_or("unknown").to_string();
        let rest = parts.next().unwrap_or("");

        let (process_name, process_id, message) = parse_process_and_message(rest);
        let event_type = classify_event(&process_name, &message);
        let severity = classify_severity(&message);

        let mut event = TelemetryEvent::new(
            self.device_id.clone(),
            hostname,
            timestamp,
            event_type,
            LogSource::Syslog,
            severity,
            raw_line.to_string(),
        );
        event.process_name = Some(process_name);
        event.process_id = process_id;

        Ok(event)
    }
}

// extract "process[pid]: message"
fn parse_process_and_message(rest: &str) -> (String, Option<u32>, String) {
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

// classify event type from process + message
fn classify_event(process_name: &str, message: &str) -> EventType {
    let pname = process_name.to_lowercase();
    let msg = message.to_lowercase();

    if pname == "sshd"
        || pname == "login"
        || msg.contains("authentication")
        || msg.contains("password")
    {
        return EventType::Authentication;
    }
    if pname == "sudo" || msg.contains("privilege") || msg.contains("escalat") {
        return EventType::PrivilegeEscalation;
    }
    if msg.contains("connect") || msg.contains("port") || msg.contains("tcp") || msg.contains("udp")
    {
        return EventType::NetworkConnection;
    }
    if msg.contains("open")
        || msg.contains("read")
        || msg.contains("write")
        || msg.contains("access")
    {
        return EventType::FileAccess;
    }
    if msg.contains("exec")
        || msg.contains("started")
        || msg.contains("command")
        || msg.contains("scan")
        || msg.contains("brute force")
        || msg.contains("crack")
        || msg.contains("loading")
        || msg.contains("fuzzing")
    {
        return EventType::ProcessExecution;
    }

    EventType::SystemEvent
}

// classify severity from message keywords
fn classify_severity(message: &str) -> Severity {
    let msg = message.to_lowercase();

    if msg.contains("fail")
        || msg.contains("error")
        || msg.contains("denied")
        || msg.contains("invalid")
    {
        return Severity::High;
    }
    if msg.contains("warn") || msg.contains("refused") || msg.contains("timeout") {
        return Severity::Medium;
    }
    if msg.contains("accepted") || msg.contains("success") || msg.contains("opened") {
        return Severity::Low;
    }

    Severity::Info
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::Parser;

    fn parser() -> LogParser {
        LogParser::new("test-device".into())
    }

    #[test]
    fn parses_standard_syslog_line() {
        let line = "Mar 10 10:00:00 webserver nginx[1234]: GET /index.html 200";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.hostname, "webserver");
        assert_eq!(event.process_name.as_deref(), Some("nginx"));
        assert_eq!(event.process_id, Some(1234));
        assert_eq!(event.device_id, "test-device");
    }

    #[test]
    fn parses_line_without_pid() {
        let line = "Mar 10 10:00:00 myhost kernel: some kernel message";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.process_name.as_deref(), Some("kernel"));
        assert_eq!(event.process_id, None);
    }

    #[test]
    fn classifies_auth_event() {
        let line = "Mar 10 10:00:00 host sshd[500]: Failed password for root from 1.2.3.4";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.event_type, EventType::Authentication);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn classifies_privilege_escalation() {
        let line = "Mar 10 10:00:00 host sudo[600]: user1 : TTY=pts/0 ; COMMAND=/bin/bash";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.event_type, EventType::PrivilegeEscalation);
    }

    #[test]
    fn classifies_system_event_as_default() {
        let line = "Mar 10 10:00:00 host cron[700]: job completed";
        let event = parser().parse(line).unwrap();
        assert_eq!(event.event_type, EventType::SystemEvent);
        assert_eq!(event.severity, Severity::Info);
    }

    #[test]
    fn rejects_short_line() {
        assert!(parser().parse("too short").is_err());
    }

    #[test]
    fn parsed_event_serializes() {
        let line = "Mar 10 10:00:00 host sshd[1]: test message";
        let event = parser().parse(line).unwrap();
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("sshd"));
    }
}
