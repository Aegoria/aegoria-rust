use tracing::debug;

use crate::core::telemetry_event::{EventType, Severity, TelemetryEvent};

// detect login failure → privilege escalation sequence
pub fn correlate_login_then_escalation(events: &[TelemetryEvent]) -> Vec<String> {
    let mut findings = Vec::new();

    let failed_users: Vec<&str> = events
        .iter()
        .filter(|e| {
            e.event_type == EventType::Authentication
                && (e.severity == Severity::High || e.severity == Severity::Critical)
        })
        .filter_map(|e| e.username.as_deref())
        .collect();

    for event in events
        .iter()
        .filter(|e| e.event_type == EventType::PrivilegeEscalation)
    {
        if let Some(ref user) = event.username
            && failed_users.contains(&user.as_str())
        {
            let msg = format!(
                "possible account compromise: failed logins then escalation by {}",
                user
            );
            debug!("{}", msg);
            if !findings.contains(&msg) {
                findings.push(msg);
            }
        }
    }

    findings
}

// detect login → suspicious process execution
pub fn correlate_login_then_recon(events: &[TelemetryEvent]) -> Vec<String> {
    let mut findings = Vec::new();

    let has_login = events
        .iter()
        .any(|e| e.event_type == EventType::Authentication && e.severity == Severity::Low);

    if !has_login {
        return findings;
    }

    for event in events
        .iter()
        .filter(|e| e.event_type == EventType::ProcessExecution)
    {
        if let Some(ref name) = event.process_name {
            let lower = name.to_lowercase();
            if is_recon_tool(&lower) {
                let msg = format!("possible reconnaissance: login then {} execution", lower);
                debug!("{}", msg);
                if !findings.contains(&msg) {
                    findings.push(msg);
                }
            }
        }
    }

    findings
}

// detect excessive connections + suspicious port combo
pub fn correlate_connections_and_suspicious_port(events: &[TelemetryEvent]) -> Vec<String> {
    let mut findings = Vec::new();

    let suspicious_ports: &[u16] = &[4444, 5555, 6666, 1337, 31337];
    let net_events: Vec<&TelemetryEvent> = events
        .iter()
        .filter(|e| e.event_type == EventType::NetworkConnection)
        .collect();

    if net_events.len() < 5 {
        return findings;
    }

    let has_suspicious_port = net_events.iter().any(|e| {
        e.network_port
            .is_some_and(|p| suspicious_ports.contains(&p))
    });

    if has_suspicious_port {
        let msg = format!(
            "possible reverse shell: {} connections with suspicious port usage",
            net_events.len()
        );
        debug!("{}", msg);
        findings.push(msg);
    }

    findings
}

fn is_recon_tool(name: &str) -> bool {
    matches!(
        name,
        "nmap" | "masscan" | "nikto" | "gobuster" | "dirb" | "wfuzz"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::log_source::LogSource;
    use chrono::Utc;

    fn make_event(event_type: EventType, severity: Severity) -> TelemetryEvent {
        TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            event_type,
            LogSource::AuthLog,
            severity,
            "raw".into(),
        )
    }

    #[test]
    fn correlates_failed_login_then_escalation() {
        let mut fail = make_event(EventType::Authentication, Severity::High);
        fail.username = Some("admin".into());

        let mut esc = make_event(EventType::PrivilegeEscalation, Severity::Medium);
        esc.username = Some("admin".into());

        let findings = correlate_login_then_escalation(&[fail, esc]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("admin"));
    }

    #[test]
    fn no_correlation_without_matching_user() {
        let mut fail = make_event(EventType::Authentication, Severity::High);
        fail.username = Some("bob".into());

        let mut esc = make_event(EventType::PrivilegeEscalation, Severity::Medium);
        esc.username = Some("alice".into());

        assert!(correlate_login_then_escalation(&[fail, esc]).is_empty());
    }

    #[test]
    fn correlates_login_then_recon() {
        let login = make_event(EventType::Authentication, Severity::Low);

        let mut proc = make_event(EventType::ProcessExecution, Severity::Info);
        proc.process_name = Some("nmap".into());

        let findings = correlate_login_then_recon(&[login, proc]);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("nmap"));
    }

    #[test]
    fn no_recon_without_login() {
        let mut proc = make_event(EventType::ProcessExecution, Severity::Info);
        proc.process_name = Some("nmap".into());

        assert!(correlate_login_then_recon(&[proc]).is_empty());
    }

    #[test]
    fn correlates_connections_with_suspicious_port() {
        let mut events = Vec::new();
        for _ in 0..6 {
            let mut e = make_event(EventType::NetworkConnection, Severity::Info);
            e.source_ip = Some("10.0.0.1".into());
            events.push(e);
        }
        // add one with suspicious port
        let mut e = make_event(EventType::NetworkConnection, Severity::Info);
        e.network_port = Some(4444);
        events.push(e);

        let findings = correlate_connections_and_suspicious_port(&events);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("reverse shell"));
    }

    #[test]
    fn no_reverse_shell_with_few_connections() {
        let mut e = make_event(EventType::NetworkConnection, Severity::Info);
        e.network_port = Some(4444);

        assert!(correlate_connections_and_suspicious_port(&[e]).is_empty());
    }
}
