use std::collections::HashSet;

// known malicious ips for enrichment
pub struct IpReputationDb {
    malicious: HashSet<String>,
}

impl IpReputationDb {
    pub fn new() -> Self {
        let mut malicious = HashSet::new();
        // test dataset of known malicious ips
        for ip in KNOWN_MALICIOUS_IPS {
            malicious.insert(ip.to_string());
        }
        Self { malicious }
    }

    pub fn is_malicious(&self, ip: &str) -> bool {
        self.malicious.contains(ip)
    }

    pub fn lookup(&self, ip: &str) -> Vec<String> {
        if self.is_malicious(ip) {
            vec!["known malicious source".into()]
        } else {
            vec![]
        }
    }
}

impl Default for IpReputationDb {
    fn default() -> Self {
        Self::new()
    }
}

const KNOWN_MALICIOUS_IPS: &[&str] = &[
    "45.33.32.156",
    "185.220.101.1",
    "103.21.244.0",
    "198.51.100.23",
    "203.0.113.42",
    "192.0.2.100",
    "91.189.114.11",
    "45.155.205.233",
    "185.56.83.83",
    "23.129.64.130",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_malicious_ip() {
        let db = IpReputationDb::new();
        assert!(db.is_malicious("45.33.32.156"));
        assert!(db.is_malicious("185.220.101.1"));
    }

    #[test]
    fn safe_ip_not_flagged() {
        let db = IpReputationDb::new();
        assert!(!db.is_malicious("8.8.8.8"));
        assert!(!db.is_malicious("192.168.1.1"));
    }

    #[test]
    fn lookup_returns_tags() {
        let db = IpReputationDb::new();
        let tags = db.lookup("45.33.32.156");
        assert_eq!(tags, vec!["known malicious source"]);
        assert!(db.lookup("10.0.0.1").is_empty());
    }
}
