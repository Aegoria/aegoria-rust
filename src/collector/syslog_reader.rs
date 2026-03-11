use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use tracing::{info, warn};

use super::Collector;

pub struct SyslogReader;

impl Collector for SyslogReader {
    fn collect(&self, path: &Path, max_lines: usize) -> anyhow::Result<Vec<String>> {
        info!("collecting syslog from {}", path.display());

        let file = File::open(path).map_err(|e| {
            warn!("failed to open syslog: {}", e);
            e
        })?;

        let reader = BufReader::new(file);

        if max_lines == 0 {
            let lines: Vec<String> = reader
                .lines()
                .filter_map(|line| match line {
                    Ok(l) if !l.trim().is_empty() => Some(l),
                    Ok(_) => None,
                    Err(e) => {
                        warn!("skipping unreadable line: {e}");
                        None
                    }
                })
                .collect();
            info!("collected {} syslog lines", lines.len());
            return Ok(lines);
        }

        // ring buffer for tail-like behavior
        let mut ring: VecDeque<String> = VecDeque::with_capacity(max_lines);

        for line in reader.lines() {
            match line {
                Ok(l) if !l.trim().is_empty() => {
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
            "collected {} syslog lines (tail {})",
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
    fn reads_all_lines() {
        let log = write_temp_log(
            "Mar 10 10:00:00 host1 kernel: something\n\
             Mar 10 10:00:01 host1 sshd[1]: test\n\
             Mar 10 10:00:02 host1 cron[2]: job\n",
        );
        let lines = SyslogReader.collect(log.path(), 0).unwrap();
        assert_eq!(lines.len(), 3);
    }

    #[test]
    fn tail_limits_lines() {
        let log = write_temp_log("line1\nline2\nline3\nline4\nline5\n");
        let lines = SyslogReader.collect(log.path(), 2).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "line4");
        assert_eq!(lines[1], "line5");
    }

    #[test]
    fn skips_empty_lines() {
        let log = write_temp_log("line1\n\n\nline2\n");
        let lines = SyslogReader.collect(log.path(), 0).unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn returns_error_for_missing_file() {
        let result = SyslogReader.collect(Path::new("/nonexistent/syslog"), 0);
        assert!(result.is_err());
    }
}
