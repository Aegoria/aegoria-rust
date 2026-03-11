pub mod authlog_reader;
pub mod syslog_reader;

use std::path::Path;

// log collection backend trait
pub trait Collector {
    // read up to max_lines recent lines; 0 = all
    fn collect(&self, path: &Path, max_lines: usize) -> anyhow::Result<Vec<String>>;
}
