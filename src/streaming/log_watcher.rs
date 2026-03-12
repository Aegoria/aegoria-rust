use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use tokio::sync::mpsc;
use tokio::time::{Duration, interval};
use tracing::{info, warn};

const POLL_INTERVAL_MS: u64 = 500;

// watches a log file and sends new lines to a channel
pub struct LogWatcher {
    path: PathBuf,
}

impl LogWatcher {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    // start tailing the file, sending new lines to tx
    pub async fn watch(&self, tx: mpsc::Sender<String>) -> anyhow::Result<()> {
        let path = &self.path;
        info!("watching {}", path.display());

        let mut file = File::open(path)?;
        // seek to end so we only get new lines
        file.seek(SeekFrom::End(0))?;
        let mut reader = BufReader::new(file);
        let mut tick = interval(Duration::from_millis(POLL_INTERVAL_MS));

        loop {
            tick.tick().await;

            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break, // no new data
                    Ok(_) => {
                        let trimmed = line.trim().to_string();
                        if !trimmed.is_empty() && tx.send(trimmed).await.is_err() {
                            info!("watcher channel closed for {}", path.display());
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        warn!("read error on {}: {}", path.display(), e);
                        break;
                    }
                }
            }
        }
    }
}

// convenience: watch a path in a spawned task
pub fn spawn_watcher(path: &Path, tx: mpsc::Sender<String>) -> tokio::task::JoinHandle<()> {
    let watcher = LogWatcher::new(path.to_path_buf());
    tokio::spawn(async move {
        if let Err(e) = watcher.watch(tx).await {
            warn!("watcher exited with error: {}", e);
        }
    })
}
