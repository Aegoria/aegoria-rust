use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{RwLock, mpsc};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::analyzer::Analyzer;
use crate::analyzer::behavior_engine::BehaviorEngine;
use crate::core::telemetry_event::TelemetryEvent;
use crate::parser::auth_parser::AuthParser;
use crate::parser::log_parser::LogParser;
use crate::parser::Parser;
use crate::reports::recommendation_engine::RecommendationEngine;
use crate::reports::report_builder::SecurityReport;
use crate::risk::scoring_engine::ScoringEngine;
use crate::threat_intel::intel_engine::IntelEngine;

use super::log_watcher;

// shared streaming state
pub struct StreamState {
    pub running: Arc<RwLock<bool>>,
    handles: Vec<JoinHandle<()>>,
    processor: Option<JoinHandle<()>>,
}

impl StreamState {
    pub fn new() -> Self {
        Self {
            running: Arc::new(RwLock::new(false)),
            handles: Vec::new(),
            processor: None,
        }
    }

    // start streaming from syslog and auth log
    pub async fn start(
        &mut self,
        syslog_path: &Path,
        authlog_path: &Path,
        report: Arc<RwLock<Option<SecurityReport>>>,
    ) {
        {
            let mut running = self.running.write().await;
            if *running {
                info!("stream already running");
                return;
            }
            *running = true;
        }

        let (tx, rx) = mpsc::channel::<String>(4096);

        // spawn watchers for each log source
        if syslog_path.exists() {
            self.handles.push(log_watcher::spawn_watcher(syslog_path, tx.clone()));
        } else {
            warn!("syslog not found, skipping: {}", syslog_path.display());
        }

        if authlog_path.exists() {
            self.handles.push(log_watcher::spawn_watcher(authlog_path, tx.clone()));
        } else {
            warn!("auth log not found, skipping: {}", authlog_path.display());
        }

        // drop extra tx so channel closes when watchers stop
        drop(tx);

        // spawn processing loop
        let running = self.running.clone();
        self.processor = Some(tokio::spawn(async move {
            process_stream(rx, report, running).await;
        }));

        info!("streaming started");
    }

    pub async fn stop(&mut self) {
        let mut running = self.running.write().await;
        *running = false;
        drop(running);

        for h in self.handles.drain(..) {
            h.abort();
        }
        if let Some(p) = self.processor.take() {
            p.abort();
        }
        info!("streaming stopped");
    }
}

const BATCH_SIZE: usize = 50;
const BATCH_TIMEOUT_MS: u64 = 2000;

// process incoming lines in batches
async fn process_stream(
    mut rx: mpsc::Receiver<String>,
    report: Arc<RwLock<Option<SecurityReport>>>,
    running: Arc<RwLock<bool>>,
) {
    let syslog_parser = LogParser::new("aegoria-stream".into());
    let auth_parser = AuthParser::new("aegoria-stream".into());
    let intel = IntelEngine::default();

    let mut batch: Vec<TelemetryEvent> = Vec::with_capacity(BATCH_SIZE);

    loop {
        if !*running.read().await {
            break;
        }

        let deadline = tokio::time::sleep(tokio::time::Duration::from_millis(BATCH_TIMEOUT_MS));
        tokio::pin!(deadline);

        // collect events until batch full or timeout
        loop {
            tokio::select! {
                line = rx.recv() => {
                    match line {
                        Some(l) => {
                            // try auth parser first, fall back to syslog
                            let event = auth_parser.parse(&l)
                                .or_else(|_| syslog_parser.parse(&l));
                            if let Ok(mut e) = event {
                                intel.enrich(&mut e);
                                batch.push(e);
                            }
                            if batch.len() >= BATCH_SIZE {
                                break;
                            }
                        }
                        None => return, // channel closed
                    }
                }
                _ = &mut deadline => {
                    break;
                }
            }
        }

        if batch.is_empty() {
            continue;
        }

        let start = Instant::now();
        let analysis = BehaviorEngine.analyze(&batch);
        let risk = ScoringEngine.score(&analysis);
        let recs = RecommendationEngine.generate(&analysis);
        let new_report = SecurityReport::build(&risk, &analysis, batch.len(), recs);

        {
            let mut stored = report.write().await;
            *stored = Some(new_report);
        }

        info!(
            "stream batch: {} events, score={}, duration_ms={}",
            batch.len(),
            risk.total_score,
            start.elapsed().as_millis()
        );

        batch.clear();
    }
}
