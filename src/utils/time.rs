use chrono::{DateTime, NaiveDateTime, Utc};

// parse syslog timestamp (e.g. "Mar 10 10:00:00")
pub fn parse_syslog_timestamp(raw: &str) -> anyhow::Result<DateTime<Utc>> {
    let year = Utc::now().format("%Y");
    let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    let with_year = format!("{year} {normalized}");
    let naive = NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")?;
    Ok(naive.and_utc())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_syslog_timestamp() {
        let dt = parse_syslog_timestamp("Mar 10 10:00:00").unwrap();
        assert_eq!(dt.format("%m-%d %H:%M:%S").to_string(), "03-10 10:00:00");
    }

    #[test]
    fn parses_double_space_day() {
        let dt = parse_syslog_timestamp("Mar  1 09:30:00").unwrap();
        assert_eq!(dt.format("%m-%d %H:%M:%S").to_string(), "03-01 09:30:00");
    }

    #[test]
    fn rejects_invalid_timestamp() {
        assert!(parse_syslog_timestamp("not a timestamp").is_err());
    }
}
