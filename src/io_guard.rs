use anyhow::{Result, anyhow};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoMode {
    Strict,
    Fast,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoOptions {
    pub mode: IoMode,
    pub read_retries: usize,
    pub write_retries: usize,
    pub durability_sync: bool,
}

impl IoOptions {
    pub fn strict() -> Self {
        Self {
            mode: IoMode::Strict,
            read_retries: 3,
            write_retries: 3,
            durability_sync: true,
        }
    }

    pub fn fast() -> Self {
        Self {
            mode: IoMode::Fast,
            read_retries: 1,
            write_retries: 1,
            durability_sync: false,
        }
    }

    fn read_attempts(&self) -> usize {
        self.read_retries.max(1)
    }

    fn write_attempts(&self) -> usize {
        self.write_retries.max(1)
    }
}

impl Default for IoOptions {
    fn default() -> Self {
        Self::strict()
    }
}

pub fn read_verified(
    path: &Path,
    expected_hash: &str,
    options: IoOptions,
) -> Result<Option<Vec<u8>>> {
    let attempts = options.read_attempts();
    for attempt in 0..attempts {
        match fs::read(path) {
            Ok(data) => {
                let hash = blake3::hash(&data).to_hex().to_string();
                if hash == expected_hash {
                    return Ok(Some(data));
                }
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    return Ok(None);
                }
            }
        }

        if attempt + 1 < attempts {
            thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    Ok(None)
}

pub fn write_atomic_verified(
    path: &Path,
    bytes: &[u8],
    expected_hash: &str,
    options: IoOptions,
) -> Result<()> {
    let attempts = options.write_attempts();
    let mut last_err: Option<anyhow::Error> = None;

    for attempt in 0..attempts {
        let temp_path = make_temp_path(path, attempt)?;

        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp_path)?;
            file.write_all(bytes)?;
            if options.durability_sync {
                file.sync_data()?;
            }
            drop(file);

            fs::rename(&temp_path, path)?;

            if options.durability_sync {
                sync_parent_dir(path)?;
            }

            let persisted = fs::read(path)?;
            let persisted_hash = blake3::hash(&persisted).to_hex().to_string();
            if persisted_hash != expected_hash {
                return Err(anyhow!("Verification hash mismatch at {}", path.display()));
            }

            Ok(())
        })();

        let _ = fs::remove_file(&temp_path);

        match result {
            Ok(_) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
            }
        }
    }

    Err(anyhow!(
        "Failed to atomically write {} after {} attempts: {}",
        path.display(),
        attempts,
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path has no parent: {}", path.display()))?;
    let dir = OpenOptions::new().read(true).open(parent)?;
    dir.sync_all()?;
    Ok(())
}

fn make_temp_path(path: &Path, attempt: usize) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Path has no file name: {}", path.display()))?
        .to_string_lossy();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("System time error: {}", e))?;
    let nonce = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);

    let temp_name = format!(
        ".{}.tmp.{}.{}.{}.{}",
        file_name,
        std::process::id(),
        now.as_secs(),
        now.subsec_nanos(),
        nonce + attempt as u64
    );

    Ok(path.with_file_name(temp_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_write_atomic_verified_rejects_bad_expected_hash() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("file.bin");

        let err = write_atomic_verified(&path, b"payload", "bad-hash", IoOptions::strict())
            .expect_err("write should fail verification");

        assert!(err.to_string().contains("Failed to atomically write"));
    }

    #[test]
    fn test_read_verified_missing_returns_none() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("missing.bin");

        let result =
            read_verified(&path, "irrelevant", IoOptions::strict()).expect("read should not error");
        assert!(result.is_none());
    }

    #[test]
    fn test_read_verified_hash_mismatch_returns_none() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("mismatch.bin");
        fs::write(&path, b"data").expect("write");

        let result =
            read_verified(&path, "bad-hash", IoOptions::strict()).expect("read should not error");
        assert!(result.is_none());
    }

    #[test]
    fn test_read_verified_recovers_after_transient_mismatch() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("flaky.bin");
        fs::write(&path, b"bad").expect("write bad");

        let expected = blake3::hash(b"good").to_hex().to_string();
        let path_for_thread = path.clone();

        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(2));
            fs::write(path_for_thread, b"good").expect("write good");
        });

        let options = IoOptions {
            mode: IoMode::Strict,
            read_retries: 5,
            write_retries: 1,
            durability_sync: true,
        };
        let data = read_verified(&path, &expected, options).expect("read");
        writer.join().expect("join");

        assert_eq!(data, Some(b"good".to_vec()));
    }
}
