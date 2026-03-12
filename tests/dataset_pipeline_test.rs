// dataset pipeline integration tests

use std::path::Path;

use aegoria_rust::analyzer::Analyzer;
use aegoria_rust::analyzer::behavior_engine::BehaviorEngine;
use aegoria_rust::analyzer::timeline::AttackTimeline;
use aegoria_rust::core::telemetry_event::TelemetryEvent;
use aegoria_rust::parser::Parser;
use aegoria_rust::parser::auth_parser::AuthParser;
use aegoria_rust::parser::log_parser::LogParser;
use aegoria_rust::reports::recommendation_engine::RecommendationEngine;
use aegoria_rust::reports::report_builder::SecurityReport;
use aegoria_rust::risk::scoring_engine::ScoringEngine;
use aegoria_rust::threat_intel::intel_engine::IntelEngine;

const DEVICE_ID: &str = "dataset-test";

fn parse_directory(dir: &Path) -> Vec<TelemetryEvent> {
    let log_parser = LogParser::new(DEVICE_ID.into());
    let auth_parser = AuthParser::new(DEVICE_ID.into());
    let intel = IntelEngine::default();

    let mut events = Vec::new();

    if !dir.exists() {
        return events;
    }

    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_type().unwrap().is_file() {
            continue;
        }
        let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let event = auth_parser
                .parse(trimmed)
                .or_else(|_| log_parser.parse(trimmed));
            if let Ok(mut e) = event {
                intel.enrich(&mut e);
                events.push(e);
            }
        }
    }

    events
}

#[test]
fn linux_dataset_full_pipeline() {
    let dir = Path::new("testdata/linux");
    let events = parse_directory(dir);

    assert!(
        events.len() > 100,
        "expected >100 linux events, got {}",
        events.len()
    );

    let analysis = BehaviorEngine.analyze(&events);
    let risk = ScoringEngine.score(&analysis);
    let recs = RecommendationEngine.generate(&analysis);
    let report = SecurityReport::build(&risk, &analysis, &events, recs);

    assert!(report.risk_score > 0, "linux dataset should detect threats");
    assert!(
        !report.recommendations.is_empty(),
        "should produce recommendations"
    );

    // verify timeline
    assert!(
        !report.attack_timeline.events.is_empty(),
        "should produce attack timeline"
    );

    // verify serialization
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("attack_timeline"));
}

#[test]
fn macos_dataset_full_pipeline() {
    let dir = Path::new("testdata/macos");
    let events = parse_directory(dir);

    assert!(
        events.len() > 100,
        "expected >100 macos events, got {}",
        events.len()
    );

    let analysis = BehaviorEngine.analyze(&events);
    let risk = ScoringEngine.score(&analysis);
    let recs = RecommendationEngine.generate(&analysis);
    let report = SecurityReport::build(&risk, &analysis, &events, recs);

    assert!(report.events_processed > 0);
    assert!(!report.recommendations.is_empty());
}

#[test]
fn windows_dataset_full_pipeline() {
    let dir = Path::new("testdata/windows");
    let events = parse_directory(dir);

    assert!(
        events.len() > 100,
        "expected >100 windows events, got {}",
        events.len()
    );

    let analysis = BehaviorEngine.analyze(&events);
    let risk = ScoringEngine.score(&analysis);
    let recs = RecommendationEngine.generate(&analysis);
    let report = SecurityReport::build(&risk, &analysis, &events, recs);

    assert!(report.events_processed > 0);
    assert!(!report.recommendations.is_empty());
}

#[test]
fn combined_dataset_stress_test() {
    let mut all_events = Vec::new();
    all_events.extend(parse_directory(Path::new("testdata/linux")));
    all_events.extend(parse_directory(Path::new("testdata/macos")));
    all_events.extend(parse_directory(Path::new("testdata/windows")));

    assert!(
        all_events.len() > 300,
        "expected >300 combined events, got {}",
        all_events.len()
    );

    let analysis = BehaviorEngine.analyze(&all_events);
    let risk = ScoringEngine.score(&analysis);
    let recs = RecommendationEngine.generate(&analysis);
    let report = SecurityReport::build(&risk, &analysis, &all_events, recs);

    // combined dataset should find significant threats
    assert!(report.risk_score > 0);
    assert!(!report.attack_timeline.events.is_empty());
    assert!(!report.detected_threats.suspicious_processes.is_empty());

    // verify json roundtrip
    let json = serde_json::to_string_pretty(&report).unwrap();
    let _: SecurityReport = serde_json::from_str(&json).unwrap();
}

#[test]
fn threat_enrichment_tags_malicious_ips() {
    let mut all_events = Vec::new();
    all_events.extend(parse_directory(Path::new("testdata/linux")));
    all_events.extend(parse_directory(Path::new("testdata/macos")));
    all_events.extend(parse_directory(Path::new("testdata/windows")));

    let tagged: Vec<_> = all_events
        .iter()
        .filter(|e| !e.threat_tags.is_empty())
        .collect();

    assert!(
        !tagged.is_empty(),
        "expected some events enriched with threat tags"
    );
}

#[test]
fn timeline_sorts_chronologically() {
    let events = parse_directory(Path::new("testdata/linux"));
    let timeline = AttackTimeline::build(&events);

    if timeline.events.len() > 1 {
        for window in timeline.events.windows(2) {
            assert!(
                window[0].timestamp <= window[1].timestamp,
                "timeline must be sorted"
            );
        }
    }
}
