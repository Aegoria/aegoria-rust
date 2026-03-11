use crate::core::telemetry_event::TelemetryEvent;

use super::ip_reputation::IpReputationDb;

// enriches events with threat intelligence
pub struct IntelEngine {
    ip_db: IpReputationDb,
}

impl IntelEngine {
    pub fn new() -> Self {
        Self {
            ip_db: IpReputationDb::new(),
        }
    }

    // enrich a single event with threat tags
    pub fn enrich(&self, event: &mut TelemetryEvent) {
        if let Some(ref ip) = event.source_ip {
            let tags = self.ip_db.lookup(ip);
            if !tags.is_empty() {
                event.threat_tags.extend(tags);
            }
        }

        if let Some(ref ip) = event.destination_ip {
            let tags = self.ip_db.lookup(ip);
            for tag in tags {
                let dest_tag = format!("{} (destination)", tag);
                event.threat_tags.push(dest_tag);
            }
        }
    }

    // enrich a batch of events
    pub fn enrich_batch(&self, events: &mut [TelemetryEvent]) {
        for event in events.iter_mut() {
            self.enrich(event);
        }
    }
}

impl Default for IntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::core::log_source::LogSource;
    use crate::core::telemetry_event::{EventType, Severity};

    #[test]
    fn enriches_malicious_source_ip() {
        let engine = IntelEngine::new();
        let mut event = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::Authentication,
            LogSource::AuthLog,
            Severity::High,
            "raw".into(),
        );
        event.source_ip = Some("45.33.32.156".into());
        engine.enrich(&mut event);
        assert!(event.threat_tags.contains(&"known malicious source".to_string()));
    }

    #[test]
    fn no_tags_for_clean_ip() {
        let engine = IntelEngine::new();
        let mut event = TelemetryEvent::new(
            "d".into(),
            "h".into(),
            Utc::now(),
            EventType::Authentication,
            LogSource::AuthLog,
            Severity::Info,
            "raw".into(),
        );
        event.source_ip = Some("8.8.8.8".into());
        engine.enrich(&mut event);
        assert!(event.threat_tags.is_empty());
    }

    #[test]
    fn enriches_batch() {
        let engine = IntelEngine::new();
        let mut events = vec![
            TelemetryEvent::new(
                "d".into(), "h".into(), Utc::now(),
                EventType::Authentication, LogSource::AuthLog,
                Severity::High, "raw".into(),
            ),
            TelemetryEvent::new(
                "d".into(), "h".into(), Utc::now(),
                EventType::Authentication, LogSource::AuthLog,
                Severity::High, "raw".into(),
            ),
        ];
        events[0].source_ip = Some("45.33.32.156".into());
        events[1].source_ip = Some("10.0.0.1".into());

        engine.enrich_batch(&mut events);
        assert!(!events[0].threat_tags.is_empty());
        assert!(events[1].threat_tags.is_empty());
    }
}
