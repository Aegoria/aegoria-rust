// full pipeline integration test

use aegoria_rust::analyzer::Analyzer;
use aegoria_rust::analyzer::behavior_engine::BehaviorEngine;
use aegoria_rust::parser::Parser;
use aegoria_rust::parser::auth_parser::AuthParser;
use aegoria_rust::parser::log_parser::LogParser;
use aegoria_rust::reports::recommendation_engine::RecommendationEngine;
use aegoria_rust::reports::report_builder::SecurityReport;
use aegoria_rust::risk::scoring_engine::ScoringEngine;

const DEVICE_ID: &str = "test-device";

fn sample_auth_logs() -> Vec<&'static str> {
    vec![
        "Mar 10 10:00:00 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Mar 10 10:00:01 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Mar 10 10:00:02 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Mar 10 10:00:03 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Mar 10 10:00:04 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Mar 10 10:00:05 host sshd[100]: Failed password for root from 10.0.0.1 port 22 ssh2",
        "Mar 10 10:01:00 host sudo[200]: root : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash",
    ]
}

fn sample_syslog_lines() -> Vec<&'static str> {
    vec!["Mar 10 10:02:00 host nmap[300]: Starting Nmap scan"]
}

#[test]
fn full_pipeline_produces_report() {
    let auth_parser = AuthParser::new(DEVICE_ID.into());
    let log_parser = LogParser::new(DEVICE_ID.into());

    // parse all events
    let mut events = Vec::new();
    for line in sample_auth_logs() {
        events.push(auth_parser.parse(line).expect("parse auth line"));
    }
    for line in sample_syslog_lines() {
        events.push(log_parser.parse(line).expect("parse syslog line"));
    }

    assert_eq!(events.len(), 8);

    // analyze
    let analysis = BehaviorEngine.analyze(&events);

    assert!(analysis.failed_logins >= 1, "should detect login burst");
    assert!(
        analysis.privilege_escalations >= 1,
        "should detect escalation"
    );

    // correlation: failed logins by root + escalation by root
    assert!(
        !analysis.correlation_findings.is_empty(),
        "should produce correlation findings"
    );

    // score
    let risk = ScoringEngine.score(&analysis);
    assert!(risk.total_score > 0, "risk score should be nonzero");

    // recommendations
    let recs = RecommendationEngine.generate(&analysis);
    assert!(!recs.is_empty(), "should produce recommendations");

    // build report
    let report = SecurityReport::build(&risk, &analysis, events.len(), recs);
    assert_eq!(report.events_processed, 8);
    assert!(report.risk_score > 0);
    assert!(!report.correlation_findings.is_empty());
    assert!(!report.recommendations.is_empty());

    // verify serialization
    let json = serde_json::to_string_pretty(&report).expect("serialize report");
    assert!(json.contains("risk_score"));
    assert!(json.contains("correlation_findings"));
    assert!(json.contains("detected_threats"));
}

#[test]
fn clean_system_produces_low_risk() {
    let log_parser = LogParser::new(DEVICE_ID.into());

    let events: Vec<_> = vec![
        "Mar 10 10:00:00 host cron[1]: job completed",
        "Mar 10 10:00:01 host kernel: all good",
    ]
    .into_iter()
    .filter_map(|line| log_parser.parse(line).ok())
    .collect();

    let analysis = BehaviorEngine.analyze(&events);
    let risk = ScoringEngine.score(&analysis);

    assert_eq!(risk.total_score, 0);
    assert_eq!(risk.level, aegoria_rust::core::risk_score::RiskLevel::Low);

    let recs = RecommendationEngine.generate(&analysis);
    assert!(recs[0].contains("no immediate action"));
}

#[test]
fn ai_json_export_works() {
    let parser = AuthParser::new(DEVICE_ID.into());
    let event = parser
        .parse("Mar 10 10:00:00 host sshd[500]: Failed password for root from 1.2.3.4 port 22 ssh2")
        .unwrap();

    let ai = event.to_ai_json();
    assert_eq!(ai["username"], "root");
    assert_eq!(ai["source_ip"], "1.2.3.4");
    assert_eq!(ai["mitre_technique"], "T1110");
    assert!(ai["timestamp"].is_string());
}
