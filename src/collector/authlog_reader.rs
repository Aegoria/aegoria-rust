use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use tracing::{info, warn};

use super::Collector;

pub struct AuthLogReader;

impl Collector for AuthLogReader {
    fn collect(&self, path: &Path, max_lines: usize) -> anyhow::Result<Vec<String>> {
        info!("collecting auth log from {}", path.display());

        let file = File::open(path).map_err(|e| {
            warn!("failed to open auth log: {}", e);
            e
        })?;

        let reader = BufReader::new(file);

        // filter for auth-related keywords
        let is_auth_line = |line: &str| -> bool {
            let lower = line.to_lowercase();
            lower.contains("sshd")
                || lower.contains("sudo")
                || lower.contains("login")
                || lower.contains("pam")
                || lower.contains("su[")
                || lower.contains("su:")
                || lower.contains("authentication")
                || lower.contains("password")
                || lower.contains("session opened")
                || lower.contains("session closed")
        };

        if max_lines == 0 {
            let lines: Vec<String> = reader
                .lines()
                .filter_map(|line| match line {
                    Ok(l) if !l.trim().is_empty() && is_auth_line(&l) => Some(l),
                    Ok(_) => None,
                    Err(e) => {
                        warn!("skipping unreadable line: {e}");
                        None
                    }
                })
                .collect();
            info!("collected {} auth log lines", lines.len());
            return Ok(lines);
        }

        let mut ring: VecDeque<String> = VecDeque::with_capacity(max_lines);

        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() && is_auth_line(&l) => {
                    if ring.len() == max_lines {
                        ring.pop_front();
                    }
                    ring.push_back(l);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("skipping unreadable line: {e}");
                }
            }
        }

        let lines: Vec<String> = ring.into_iter().collect();
        info!(
            "collected {} auth log lines (tail {})",
            lines.len(),
            max_lines
        );
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_log(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn filters_auth_lines_only() {
        let log = write_temp_log(
            "Mar 10 10:00:00 host sshd[100]: Failed password for root from 1.2.3.4\n\
             Mar 10 10:00:01 host kernel: some kernel msg\n\
             Mar 10 10:00:02 host sudo: user1 : TTY=pts/0 ; COMMAND=/bin/bash\n\
             Mar 10 10:00:03 host cron[200]: job finished\n",
        );
        let lines = AuthLogReader.collect(log.path(), 0).unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("sshd"));
        assert!(lines[1].contains("sudo"));
    }

    #[test]
    fn tail_limits_auth_lines() {
        let log = write_temp_log(
            "Mar 10 10:00:00 host sshd[1]: line1\n\
             Mar 10 10:00:01 host sshd[2]: line2\n\
             Mar 10 10:00:02 host sshd[3]: line3\n",
        );
        let lines = AuthLogReader.collect(log.path(), 2).unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("line2"));
        assert!(lines[1].contains("line3"));
    }

    #[test]
    fn handles_permission_error() {
        let result = AuthLogReader.collect(Path::new("/nonexistent/auth.log"), 0);
        assert!(result.is_err());
    }
}
