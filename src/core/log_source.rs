use serde::{Deserialize, Serialize};

// log origin identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Syslog,
    AuthLog,
}
