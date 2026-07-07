use anyhow::{Context, Result, anyhow};
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
    ///
    /// # Errors
    ///
    /// Returns an error when the audit log lock is poisoned or the event cannot be written.
    pub fn log(&self, event: &str, message: &str) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let mut file = self
            .file
            .lock()
            .map_err(|error| anyhow!("failed to lock audit log: {error}"))?;
        writeln!(file, "ts={} event={} {}", timestamp, event, message)
            .context("failed to write audit log event")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic;

    #[test]
    fn writes_audit_event_because_security_events_must_be_persisted() -> Result<()> {
        let log_file = tempfile::NamedTempFile::new()?;
        let logger = AuditLogger::new(log_file.path())?;

        logger.log("test_event", "key=value")?;

        let content = fs::read_to_string(log_file.path())?;
        assert!(content.contains("event=test_event"));
        assert!(content.contains("key=value"));
        Ok(())
    }

    #[test]
    fn returns_error_when_audit_lock_is_poisoned_because_log_loss_must_not_be_hidden() -> Result<()>
    {
        let log_file = tempfile::NamedTempFile::new()?;
        let logger = AuditLogger::new(log_file.path())?;
        let poison_result = panic::catch_unwind(|| {
            let _guard = logger.file.lock();
            panic!("poison audit log lock");
        });

        assert!(poison_result.is_err());
        let error = logger
            .log("test_event", "key=value")
            .expect_err("poisoned audit lock should fail");

        assert!(error.to_string().contains("failed to lock audit log"));
        Ok(())
    }
}
