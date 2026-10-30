//! Cleanup only for data directories created by our disposable container fixtures.
use crate::{Result, security, util};
use std::{path::Path, process::Command};

pub(crate) struct DataCleanup {
    command: Command,
    pending: bool,
}
impl DataCleanup {
    /// `data` must be the fresh owned fixture directory, never an operator path.
    pub(crate) fn new(root: &Path, data: &Path) -> Self {
        let command = util::cmd(
            "docker",
            &[
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--log-driver",
                "none",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--volume",
                &format!("{}:/data", data.display()),
                "--entrypoint",
                "rm",
                security::BUILD_IMAGE,
                "-rf",
                "/data/metadata",
                "/data/blobs",
            ],
            root,
        );
        Self {
            command,
            pending: true,
        }
    }
    /// Check cleanup before reporting success. A failed attempt remains armed for Drop.
    pub(crate) fn finish(&mut self) -> Result {
        if self.pending {
            util::cleanup(&mut self.command, 60)?;
            self.pending = false;
        }
        Ok(())
    }
}
impl Drop for DataCleanup {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_cleanup_keeps_fixed_scope_identity_and_sandbox() {
        let mut cleanup = DataCleanup::new(Path::new("/fixture"), Path::new("/fixture/owned/data"));
        // Disarm before assertions: even a failed contract test must not invoke Docker.
        cleanup.pending = false;
        assert_eq!(cleanup.command.get_program(), "docker");
        let args: Vec<_> = cleanup
            .command
            .get_args()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            args,
            [
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--log-driver",
                "none",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--volume",
                "/fixture/owned/data:/data",
                "--entrypoint",
                "rm",
                security::BUILD_IMAGE,
                "-rf",
                "/data/metadata",
                "/data/blobs",
            ]
        );
    }

    #[test]
    fn cleanup_failure_stays_armed_and_success_is_idempotent() -> Result {
        let mut cleanup = DataCleanup {
            command: Command::new("false"),
            pending: true,
        };
        assert!(cleanup.finish().is_err());
        assert!(cleanup.pending);
        cleanup.command = Command::new("true");
        cleanup.finish()?;
        assert!(!cleanup.pending);
        cleanup.command = Command::new("false");
        cleanup.finish()
    }

    #[test]
    fn cancelled_data_cleanup_child() -> Result {
        let Some(directory) = std::env::var_os("XTASK_DATA_CLEANUP_CHILD") else {
            return Ok(());
        };
        let directory = std::path::PathBuf::from(directory);
        util::install_cancellation()?;
        let mut command = Command::new("touch");
        command.arg(directory.join("cleaned"));
        let mut cleanup = DataCleanup {
            command,
            pending: true,
        };
        std::fs::write(directory.join("ready"), "ready")?;
        assert!(util::quiet(Command::new("sleep").arg("30"), 60).is_err());
        assert!(util::check_cancelled().is_err());
        cleanup.finish()?;
        assert!(!cleanup.pending);
        Ok(())
    }

    #[test]
    fn checked_data_cleanup_runs_after_cancellation() -> Result {
        use std::{
            process::Stdio,
            thread,
            time::{Duration, Instant},
        };
        struct ChildGuard(std::process::Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir()?;
        let mut child = ChildGuard(
            Command::new(std::env::current_exe()?)
                .args(["--exact", "fixture::tests::cancelled_data_cleanup_child"])
                .env("XTASK_DATA_CLEANUP_CHILD", temp.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !temp.path().join("ready").exists() {
            crate::ensure(
                Instant::now() < deadline && child.0.try_wait()?.is_none(),
                "Cleanup child did not start",
            )?;
            thread::sleep(Duration::from_millis(20));
        }
        let pid = rustix::process::Pid::from_raw(child.0.id() as i32).ok_or("Invalid child PID")?;
        rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait()? {
                crate::ensure(status.success(), "Canceled cleanup failed")?;
                break;
            }
            crate::ensure(Instant::now() < deadline, "Canceled cleanup timed out")?;
            thread::sleep(Duration::from_millis(20));
        }
        assert!(temp.path().join("cleaned").is_file());
        Ok(())
    }

    #[test]
    fn failed_scope_uses_drop_cleanup() -> Result {
        let temp = tempfile::tempdir()?;
        let marker = temp.path().join("cleanup-ran");
        {
            // External touch is only a disposable observable stand-in for the cleanup command.
            let mut command = Command::new("touch");
            command.arg(&marker);
            let _cleanup = DataCleanup {
                command,
                pending: true,
            };
            // No finish call: represents startup/readiness failure unwinding the fixture.
        }
        assert!(marker.is_file());
        Ok(())
    }
}
