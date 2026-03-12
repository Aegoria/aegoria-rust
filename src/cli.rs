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

const BANNER: &str = r#"
     _    _____ ____ ___  ____  ___    _
    / \  | ____/ ___/ _ \|  _ \|_ _|  / \
   / _ \ |  _|| |  | | | | |_) || |  / _ \
  / ___ \| |__| |__| |_| |  _ < | | / ___ \
 /_/   \_|_____\____\___/|_| \_|___/_/   \_\

 Observe. Detect. Protect.
"#;

// check if first arg is a cli command or directory path
pub fn try_run() -> anyhow::Result<Option<anyhow::Result<()>>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Ok(None);
    }

    let cmd = &args[1];

    // demo command: load built-in testdata
    if cmd == "demo" {
        return Ok(Some(run_demo()));
    }

    // directory path: scan it
    let path = Path::new(cmd);
    if path.is_dir() {
        return Ok(Some(run_dataset(path)));
    }

    Ok(None)
}

fn run_demo() -> anyhow::Result<()> {
    println!("{}", BANNER);
    println!(" [demo] loading synthetic dataset from testdata/\n");

    let testdata = Path::new("testdata");
    if !testdata.exists() {
        anyhow::bail!("testdata/ directory not found. run from project root.");
    }

    run_dataset(testdata)
}

fn run_dataset(dir: &Path) -> anyhow::Result<()> {
    let start = Instant::now();
    info!("cli: scanning directory {}", dir.display());

    let log_parser = LogParser::new("cli-scan".into());
    let auth_parser = AuthParser::new("cli-scan".into());
    let intel = IntelEngine::default();

    let mut all_events: Vec<TelemetryEvent> = Vec::new();
    let mut files_processed = 0u32;
    let mut lines_read = 0u32;

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
            lines_read += 1;
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
        "cli: parsed {} events from {} files ({} lines)",
        all_events.len(),
        files_processed,
        lines_read
    );

    // analyze
    info!("cli: running behavioral analysis");
    let analysis = BehaviorEngine.analyze(&all_events);

    info!("cli: computing risk score");
    let risk = ScoringEngine.score(&analysis);

    let recs = RecommendationEngine.generate(&analysis);
    let elapsed_ms = start.elapsed().as_millis();
    let report =
        SecurityReport::build_with_latency(&risk, &analysis, &all_events, recs, elapsed_ms);

    let json = serde_json::to_string_pretty(&report)?;
    println!("{}", json);

    let elapsed = start.elapsed();
    eprintln!(
        "\n--- scan complete: {} files, {} events, score={}, level={:?}, duration={:?} ---",
        files_processed,
        all_events.len(),
        risk.total_score,
        risk.level,
        elapsed
    );

    Ok(())
}
