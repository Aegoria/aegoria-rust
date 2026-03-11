// application configuration (toml loading in future)
pub struct Config {
    pub syslog_path: String,
    pub authlog_path: String,
    pub api_host: String,
    pub api_port: u16,
    pub max_scan_lines: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            syslog_path: "/var/log/syslog".into(),
            authlog_path: "/var/log/auth.log".into(),
            api_host: "0.0.0.0".into(),
            api_port: 3000,
            max_scan_lines: 1000,
        }
    }
}
