use anyhow::{Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct AuditLogger {
    file: Mutex<File>,
}

impl AuditLogger {
    /// Opens an append-only audit log file and creates parent directories when needed.
    ///
    /// # Errors
    ///
    /// Returns an error when the log directory or file cannot be opened.
    pub fn new(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open audit log {}", path.display()))?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Writes one audit log event.
    pub fn log(&self, event: &str, message: &str) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        if let Ok(mut file) = self.file.lock() {
            let _ = writeln!(file, "ts={} event={} {}", timestamp, event, message);
        }
    }
}
