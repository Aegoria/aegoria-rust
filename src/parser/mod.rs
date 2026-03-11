pub mod auth_parser;
pub mod log_parser;

use crate::core::telemetry_event::TelemetryEvent;

// raw log line → structured event
pub trait Parser {
    fn parse(&self, raw_line: &str) -> anyhow::Result<TelemetryEvent>;
}
