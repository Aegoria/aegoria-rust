use serde::{Deserialize, Serialize};

// risk level categories
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

// anomaly counts and computed risk score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    pub failed_logins: u32,
    pub privilege_escalations: u32,
    pub suspicious_processes: u32,
    pub network_anomalies: u32,
    pub total_score: u32,
    pub level: RiskLevel,
}

impl RiskScore {
    // weights: logins=25, escalations=30, processes=20, network=15
    // clamped to 0..=100
    pub fn compute(
        failed_logins: u32,
        privilege_escalations: u32,
        suspicious_processes: u32,
        network_anomalies: u32,
    ) -> Self {
        let raw = failed_logins * 25
            + privilege_escalations * 30
            + suspicious_processes * 20
            + network_anomalies * 15;

        let total_score = raw.min(100);

        let level = match total_score {
            0..=19 => RiskLevel::Low,
            20..=49 => RiskLevel::Medium,
            50..=79 => RiskLevel::High,
            _ => RiskLevel::Critical,
        };

        Self {
            failed_logins,
            privilege_escalations,
            suspicious_processes,
            network_anomalies,
            total_score,
            level,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_risk_score() {
        let score = RiskScore::compute(0, 0, 0, 1);
        assert_eq!(score.total_score, 15);
        assert_eq!(score.level, RiskLevel::Low);
    }

    #[test]
    fn medium_risk_score() {
        let score = RiskScore::compute(1, 0, 0, 0);
        // 25
        assert_eq!(score.total_score, 25);
        assert_eq!(score.level, RiskLevel::Medium);
    }

    #[test]
    fn high_risk_score() {
        let score = RiskScore::compute(1, 1, 0, 0);
        // 25 + 30 = 55
        assert_eq!(score.total_score, 55);
        assert_eq!(score.level, RiskLevel::High);
    }

    #[test]
    fn critical_risk_score() {
        let score = RiskScore::compute(2, 1, 1, 1);
        // 50 + 30 + 20 + 15 = 115 → clamped to 100
        assert_eq!(score.total_score, 100);
        assert_eq!(score.level, RiskLevel::Critical);
    }

    #[test]
    fn score_clamped_at_100() {
        let score = RiskScore::compute(10, 10, 10, 10);
        assert_eq!(score.total_score, 100);
    }

    #[test]
    fn zero_inputs_produce_zero() {
        let score = RiskScore::compute(0, 0, 0, 0);
        assert_eq!(score.total_score, 0);
        assert_eq!(score.level, RiskLevel::Low);
    }
}
