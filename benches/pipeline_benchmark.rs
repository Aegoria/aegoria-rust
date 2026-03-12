use criterion::{Criterion, black_box, criterion_group, criterion_main};

use aegoria_rust::analyzer::Analyzer;
use aegoria_rust::analyzer::behavior_engine::BehaviorEngine;
use aegoria_rust::core::log_source::LogSource;
use aegoria_rust::core::telemetry_event::{EventType, Severity, TelemetryEvent};
use aegoria_rust::reports::recommendation_engine::RecommendationEngine;
use aegoria_rust::reports::report_builder::SecurityReport;
use aegoria_rust::risk::scoring_engine::ScoringEngine;
use aegoria_rust::threat_intel::intel_engine::IntelEngine;

use chrono::Utc;

// generate n synthetic events for benchmarking
fn generate_events(n: usize) -> Vec<TelemetryEvent> {
    let event_types = [
        (EventType::Authentication, Severity::High),
        (EventType::Authentication, Severity::Low),
        (EventType::ProcessExecution, Severity::Medium),
        (EventType::NetworkConnection, Severity::Info),
        (EventType::PrivilegeEscalation, Severity::High),
        (EventType::FileAccess, Severity::Low),
        (EventType::SystemEvent, Severity::Info),
    ];

    let ips = [
        "10.0.0.1",
        "192.168.1.50",
        "45.33.32.156",
        "172.16.0.10",
        "203.0.113.42",
    ];

    let processes = [
        "sshd", "nginx", "nmap", "cron", "systemd", "bash", "python3",
    ];

    (0..n)
        .map(|i| {
            let (et, sev) = event_types[i % event_types.len()].clone();
            let mut e = TelemetryEvent::new(
                "bench-device".into(),
                "bench-host".into(),
                Utc::now(),
                et,
                LogSource::Syslog,
                sev,
                "benchmark raw log line".into(),
            );
            e.source_ip = Some(ips[i % ips.len()].into());
            e.process_name = Some(processes[i % processes.len()].into());
            e.username = Some("testuser".into());
            e.network_port = Some(443 + (i % 10) as u16);
            e
        })
        .collect()
}

fn bench_full_pipeline(c: &mut Criterion) {
    let events = generate_events(10_000);
    let intel = IntelEngine::default();

    c.bench_function("pipeline_10k_events", |b| {
        b.iter(|| {
            let mut events = events.clone();
            intel.enrich_batch(&mut events);
            let analysis = BehaviorEngine.analyze(black_box(&events));
            let risk = ScoringEngine.score(&analysis);
            let recs = RecommendationEngine.generate(&analysis);
            let _report = SecurityReport::build(&risk, &analysis, &events, recs);
        })
    });
}

fn bench_analysis_only(c: &mut Criterion) {
    let events = generate_events(10_000);

    c.bench_function("analysis_10k_events", |b| {
        b.iter(|| {
            BehaviorEngine.analyze(black_box(&events));
        })
    });
}

fn bench_threat_enrichment(c: &mut Criterion) {
    let events = generate_events(10_000);
    let intel = IntelEngine::default();

    c.bench_function("enrichment_10k_events", |b| {
        b.iter(|| {
            let mut events = events.clone();
            intel.enrich_batch(black_box(&mut events));
        })
    });
}

criterion_group!(
    benches,
    bench_full_pipeline,
    bench_analysis_only,
    bench_threat_enrichment
);
criterion_main!(benches);
