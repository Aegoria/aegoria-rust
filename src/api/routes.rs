use std::path::Path;
use std::time::Instant;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;
use tracing::{info, warn};

use super::server::AppState;
use crate::analyzer::Analyzer;
use crate::analyzer::behavior_engine::BehaviorEngine;
use crate::collector::Collector;
use crate::collector::authlog_reader::AuthLogReader;
use crate::collector::syslog_reader::SyslogReader;
use crate::core::telemetry_event::TelemetryEvent;
use crate::parser::Parser;
use crate::parser::auth_parser::AuthParser;
use crate::parser::log_parser::LogParser;
use crate::reports::recommendation_engine::RecommendationEngine;
use crate::reports::report_builder::SecurityReport;
use crate::risk::scoring_engine::ScoringEngine;

pub async fn health() -> &'static str {
    "ok"
}

pub async fn get_report(State(state): State<AppState>) -> Result<Json<SecurityReport>, StatusCode> {
    let report = state.report.read().await;
    match report.as_ref() {
        Some(r) => Ok(Json(r.clone())),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Serialize)]
pub struct ScanResponse {
    pub status: String,
    pub events_collected: usize,
    pub events_parsed: usize,
    pub events_analyzed: usize,
    pub risk_score: u32,
    pub risk_level: String,
    pub duration_ms: u128,
}

pub async fn post_scan(
    State(state): State<AppState>,
) -> Result<Json<ScanResponse>, (StatusCode, String)> {
    let start = Instant::now();
    info!("scan triggered");

    let config = &state.config;
    let max_lines = config.max_scan_lines;
    let device_id = "aegoria-local".to_string();

    // collect + parse syslog
    let mut all_events: Vec<TelemetryEvent> = Vec::new();
    let mut lines_collected: usize = 0;

    let syslog_path = Path::new(&config.syslog_path);
    if let Ok(lines) = SyslogReader.collect(syslog_path, max_lines) {
        lines_collected += lines.len();
        let parser = LogParser::new(device_id.clone());
        for line in &lines {
            if let Ok(event) = parser.parse(line) {
                all_events.push(event);
            }
        }
        info!(
            "syslog: {} lines → {} events",
            lines.len(),
            all_events.len()
        );
    } else {
        warn!("syslog collection failed, continuing");
    }

    // collect + parse auth log
    let authlog_path = Path::new(&config.authlog_path);
    let pre_count = all_events.len();
    if let Ok(lines) = AuthLogReader.collect(authlog_path, max_lines) {
        lines_collected += lines.len();
        let parser = AuthParser::new(device_id.clone());
        for line in &lines {
            if let Ok(event) = parser.parse(line) {
                all_events.push(event);
            }
        }
        info!(
            "auth log: {} lines → {} events",
            lines.len(),
            all_events.len() - pre_count
        );
    } else {
        warn!("auth log collection failed, continuing");
    }

    let events_parsed = all_events.len();

    // analyze
    let analysis = BehaviorEngine.analyze(&all_events);
    let events_analyzed = events_parsed;

    // score
    let risk = ScoringEngine.score(&analysis);
    info!("risk score: {} ({:?})", risk.total_score, risk.level);

    // recommendations + report
    let recommendations = RecommendationEngine.generate(&analysis);
    let report = SecurityReport::build(&risk, &analysis, events_parsed, recommendations);

    let risk_level_str = format!("{:?}", report.risk_level).to_lowercase();
    let risk_score_val = report.risk_score;

    {
        let mut stored = state.report.write().await;
        *stored = Some(report);
    }

    let duration_ms = start.elapsed().as_millis();
    info!(
        "scan complete: events={} duration_ms={}",
        events_parsed, duration_ms
    );

    Ok(Json(ScanResponse {
        status: "scan complete".into(),
        events_collected: lines_collected,
        events_parsed,
        events_analyzed,
        risk_score: risk_score_val,
        risk_level: risk_level_str,
        duration_ms,
    }))
}
