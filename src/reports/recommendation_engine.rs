use crate::analyzer::AnalysisResult;

pub struct RecommendationEngine;

impl RecommendationEngine {
    pub fn generate(&self, result: &AnalysisResult) -> Vec<String> {
        let mut recs = Vec::new();

        if result.failed_logins > 0 {
            recs.push(format!(
                "{} login burst(s) detected. consider ip-based rate limiting or firewall rules.",
                result.failed_logins
            ));
        }

        if result.privilege_escalations > 0 {
            recs.push(format!(
                "{} privilege escalation(s) detected. audit sudo usage and restrict elevation policies.",
                result.privilege_escalations
            ));
        }

        for proc in &result.suspicious_processes {
            recs.push(format!(
                "suspicious tool '{}' detected. investigate host for compromise.",
                proc
            ));
        }

        for anomaly in &result.network_anomalies {
            recs.push(format!(
                "network anomaly: {}. review traffic and consider monitoring.",
                anomaly
            ));
        }

        for finding in &result.correlation_findings {
            recs.push(format!(
                "correlated threat: {}. immediate investigation recommended.",
                finding
            ));
        }

        if recs.is_empty() {
            recs.push("no immediate action required.".into());
        }

        recs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_specific_recommendations() {
        let result = AnalysisResult {
            failed_logins: 2,
            privilege_escalations: 1,
            suspicious_processes: vec!["nmap".into()],
            network_anomalies: vec!["excessive connections from 10.0.0.1: 20 events".into()],
            correlation_findings: vec![
                "possible account compromise: failed logins then escalation by admin".into(),
            ],
        };
        let recs = RecommendationEngine.generate(&result);
        assert!(recs.len() >= 5);
        assert!(recs[0].contains("rate limiting"));
        assert!(recs[1].contains("sudo"));
        assert!(recs[2].contains("nmap"));
    }

    #[test]
    fn no_threats_produces_safe_message() {
        let result = AnalysisResult::default();
        let recs = RecommendationEngine.generate(&result);
        assert_eq!(recs.len(), 1);
        assert!(recs[0].contains("no immediate action"));
    }
}
