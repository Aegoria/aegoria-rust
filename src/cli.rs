use std::path::Path;
use std::time::Instant;

use tracing::info;
use walkdir::WalkDir;

use aegoria_rust::analyzer::Analyzer;
use aegoria_rust::analyzer::behavior_engine::BehaviorEngine;
use aegoria_rust::core::telemetry_event::TelemetryEvent;
use aegoria_rust::parser::Parser;
use aegoria_rust::parser::auth_parser::AuthParser;
use aegoria_rust::parser::log_parser::LogParser;
use aegoria_rust::reports::recommendation_engine::RecommendationEngine;
use aegoria_rust::reports::report_builder::SecurityReport;
use aegoria_rust::risk::scoring_engine::ScoringEngine;
use aegoria_rust::threat_intel::intel_engine::IntelEngine;

// check if first arg is a testdata directory path
pub fn try_run() -> anyhow::Result<Option<anyhow::Result<()>>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Ok(None);
    }

    let path = Path::new(&args[1]);
    if !path.is_dir() {
        return Ok(None);
    }

    Ok(Some(run_dataset(path)))
}

fn run_dataset(dir: &Path) -> anyhow::Result<()> {
    let start = Instant::now();
    info!("scanning dataset directory: {}", dir.display());

    let log_parser = LogParser::new("dataset-test".into());
    let auth_parser = AuthParser::new("dataset-test".into());
    let intel = IntelEngine::default();

    let mut all_events: Vec<TelemetryEvent> = Vec::new();
    let mut files_processed = 0u32;

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
    {
        let path = entry.path();
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        files_processed += 1;
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            // try auth parser first, fall back to syslog parser
            let event = auth_parser
                .parse(trimmed)
                .or_else(|_| log_parser.parse(trimmed));
            if let Ok(mut e) = event {
                intel.enrich(&mut e);
                all_events.push(e);
            }
        }
    }

    info!(
        "parsed {} events from {} files",
        all_events.len(),
        files_processed
    );

    // analyze
    let analysis = BehaviorEngine.analyze(&all_events);
    let risk = ScoringEngine.score(&analysis);
    let recs = RecommendationEngine.generate(&analysis);
    let report = SecurityReport::build(&risk, &analysis, &all_events, recs);

    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);

    let elapsed = start.elapsed();
    info!(
        "dataset scan complete: {} events, score={}, duration={:?}",
        all_events.len(),
        risk.total_score,
        elapsed
    );

    Ok(())
}
