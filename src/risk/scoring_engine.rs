use crate::analyzer::AnalysisResult;
use crate::core::risk_score::RiskScore;

pub struct ScoringEngine;

impl ScoringEngine {
    pub fn score(&self, result: &AnalysisResult) -> RiskScore {
        RiskScore::compute(
            result.failed_logins,
            result.privilege_escalations,
            result.suspicious_processes.len() as u32,
            result.network_anomalies.len() as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scores_analysis_result() {
        let result = AnalysisResult {
            failed_logins: 1,
            privilege_escalations: 1,
            suspicious_processes: vec!["nmap".into()],
            network_anomalies: vec![],
            correlation_findings: vec![],
        };
        let score = ScoringEngine.score(&result);
        // 25 + 30 + 20 = 75
        assert_eq!(score.total_score, 75);
    }
}
