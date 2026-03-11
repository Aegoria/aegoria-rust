use std::collections::HashMap;

use chrono::Duration;
use tracing::debug;

use crate::core::telemetry_event::{EventType, Severity, TelemetryEvent};

const FAILED_LOGIN_BURST_THRESHOLD: u32 = 5;
const BURST_WINDOW_MINUTES: i64 = 10;

const SUSPICIOUS_BINARIES: &[&str] = &[
    "nmap",
    "nc",
    "netcat",
    "hydra",
    "john",
    "sqlmap",
    "masscan",
    "nikto",
    "msfconsole",
    "metasploit",
    "hashcat",
    "gobuster",
    "dirb",
    "wfuzz",
];

// detect repeated failed logins per source ip
pub fn detect_failed_login_burst(events: &[TelemetryEvent]) -> u32 {
    let mut by_ip: HashMap<&str, Vec<&TelemetryEvent>> = HashMap::new();

    for event in events.iter().filter(|e| {
        e.event_type == EventType::Authentication
            && (e.severity == Severity::High || e.severity == Severity::Critical)
    }) {
        if let Some(ref ip) = event.source_ip {
            by_ip.entry(ip.as_str()).or_default().push(event);
        }
    }

    let window = Duration::minutes(BURST_WINDOW_MINUTES);
    let mut bursts = 0u32;

    for (ip, mut ip_events) in by_ip {
        ip_events.sort_by_key(|e| e.timestamp);

        let mut window_start = 0;
        let mut count_in_window = 0u32;

        for i in 0..ip_events.len() {
            while ip_events[i].timestamp - ip_events[window_start].timestamp > window {
                window_start += 1;
            }
            count_in_window = (i - window_start + 1) as u32;
        }

        if count_in_window >= FAILED_LOGIN_BURST_THRESHOLD {
            debug!("login burst: {} attempts from {}", count_in_window, ip);
            bursts += 1;
        }
    }

    bursts
}

// count privilege escalation events
pub fn detect_privilege_escalation(events: &[TelemetryEvent]) -> u32 {
    let count = events
        .iter()
        .filter(|e| e.event_type == EventType::PrivilegeEscalation)
        .count() as u32;

    if count > 0 {
        debug!("{} privilege escalation events", count);
    }
    count
}

// match processes against known offensive tools
pub fn detect_suspicious_processes(events: &[TelemetryEvent]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();

    for event in events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExecution)
    {
        if let Some(ref name) = event.process_name {
            let lower = name.to_lowercase();
            for &tool in SUSPICIOUS_BINARIES {
                if lower.contains(tool) && !found.contains(&lower) {
                    debug!("suspicious process: {}", name);
                    found.push(lower.clone());
                    break;
                }
            }
        }
    }

    found
}

const SUSPICIOUS_PORTS: &[u16] = &[4444, 5555, 6666, 1337, 31337, 8888];

// detect excessive connections and suspicious ports
pub fn detect_network_anomalies(events: &[TelemetryEvent]) -> Vec<String> {
    let mut anomalies: Vec<String> = Vec::new();

    let mut connections_by_ip: HashMap<&str, u32> = HashMap::new();
    for event in events
        .iter()
        .filter(|e| e.event_type == EventType::NetworkConnection)
    {
        if let Some(ref ip) = event.source_ip {
            *connections_by_ip.entry(ip.as_str()).or_default() += 1;
        }
    }

    for (ip, count) in &connections_by_ip {
        if *count > 10 {
            anomalies.push(format!("excessive connections from {ip}: {count} events"));
        }
    }

    for event in events
        .iter()
        .filter(|e| e.event_type == EventType::NetworkConnection)
    {
        if let Some(port) = event.network_port
            && SUSPICIOUS_PORTS.contains(&port)
        {
            let ip = event.source_ip.as_deref().unwrap_or("unknown");
            anomalies.push(format!("suspicious port {port} from {ip}"));
        }
    }

    anomalies
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::log_source::LogSource;
    use chrono::Utc;

    fn make_event(event_type: EventType, severity: Severity) -> TelemetryEvent {
        TelemetryEvent::new(
            "dev-1".into(),
            "host".into(),
            Utc::now(),
            event_type,
            LogSource::AuthLog,
            severity,
            "raw".into(),
        )
    }

    #[test]
    fn detects_failed_login_burst() {
        let mut events = Vec::new();
        for _ in 0..6 {
            let mut e = make_event(EventType::Authentication, Severity::High);
            e.source_ip = Some("10.0.0.1".into());
            events.push(e);
        }
        assert_eq!(detect_failed_login_burst(&events), 1);
    }

    #[test]
    fn no_burst_below_threshold() {
        let mut events = Vec::new();
        for _ in 0..3 {
            let mut e = make_event(EventType::Authentication, Severity::High);
            e.source_ip = Some("10.0.0.1".into());
            events.push(e);
        }
        assert_eq!(detect_failed_login_burst(&events), 0);
    }

    #[test]
    fn detects_multiple_ip_bursts() {
        let mut events = Vec::new();
        for ip in &["10.0.0.1", "10.0.0.2"] {
            for _ in 0..6 {
                let mut e = make_event(EventType::Authentication, Severity::High);
                e.source_ip = Some(ip.to_string());
                events.push(e);
            }
        }
        assert_eq!(detect_failed_login_burst(&events), 2);
    }

    #[test]
    fn detects_privilege_escalation() {
        let events = vec![
            make_event(EventType::PrivilegeEscalation, Severity::Medium),
            make_event(EventType::PrivilegeEscalation, Severity::Medium),
            make_event(EventType::Authentication, Severity::Info),
        ];
        assert_eq!(detect_privilege_escalation(&events), 2);
    }

    #[test]
    fn no_escalation_when_none() {
        let events = vec![make_event(EventType::Authentication, Severity::Info)];
        assert_eq!(detect_privilege_escalation(&events), 0);
    }

    #[test]
    fn detects_suspicious_process() {
        let mut e = make_event(EventType::ProcessExecution, Severity::High);
        e.process_name = Some("nmap".into());
        assert_eq!(detect_suspicious_processes(&[e]), vec!["nmap"]);
    }

    #[test]
    fn deduplicates_suspicious_processes() {
        let mut e1 = make_event(EventType::ProcessExecution, Severity::High);
        e1.process_name = Some("nmap".into());
        let mut e2 = make_event(EventType::ProcessExecution, Severity::High);
        e2.process_name = Some("nmap".into());
        assert_eq!(detect_suspicious_processes(&[e1, e2]).len(), 1);
    }

    #[test]
    fn ignores_non_execution_for_process_detection() {
        let mut e = make_event(EventType::Authentication, Severity::High);
        e.process_name = Some("nmap".into());
        assert!(detect_suspicious_processes(&[e]).is_empty());
    }

    #[test]
    fn detects_excessive_connections() {
        let mut events = Vec::new();
        for _ in 0..15 {
            let mut e = make_event(EventType::NetworkConnection, Severity::Info);
            e.source_ip = Some("192.168.1.1".into());
            events.push(e);
        }
        let anomalies = detect_network_anomalies(&events);
        assert!(!anomalies.is_empty());
        assert!(anomalies[0].contains("192.168.1.1"));
    }

    #[test]
    fn detects_suspicious_port() {
        let mut e = make_event(EventType::NetworkConnection, Severity::Info);
        e.source_ip = Some("10.0.0.5".into());
        e.network_port = Some(4444);
        let anomalies = detect_network_anomalies(&[e]);
        assert!(anomalies[0].contains("4444"));
    }

    #[test]
    fn no_anomaly_for_normal_traffic() {
        let mut e = make_event(EventType::NetworkConnection, Severity::Info);
        e.source_ip = Some("10.0.0.1".into());
        e.network_port = Some(443);
        assert!(detect_network_anomalies(&[e]).is_empty());
    }
}
