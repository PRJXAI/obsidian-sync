#![forbid(unsafe_code)]
use std::{
    fs,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use xtask::{Result, ensure, util};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// This same test executable provides a subprocess fixture; no shell/Python shim.
#[test]
fn cancellation_fixture_child() -> Result {
    let Some(directory) = std::env::var_os("XTASK_CANCELLATION_FIXTURE_DIR") else {
        return Ok(());
    };
    let directory = PathBuf::from(directory);
    util::install_cancellation()?;
    fs::write(directory.join("ready"), "ready")?;
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            // Cleanup must remain runnable after cancellation is latched.
            if util::cleanup(&mut Command::new("true"), 5).is_ok() {
                let _ = fs::write(self.0.join("cleaned"), "complete");
            }
        }
    }
    let _cleanup = Cleanup(directory);
    ensure(
        util::quiet(Command::new("sleep").arg("30"), 60).is_err(),
        "Canceled work must fail",
    )
}

#[test]
fn sigterm_unwinds_owned_work_and_preserves_cleanup() -> Result {
    let work = tempfile::tempdir()?;
    let mut c = Command::new(std::env::current_exe()?);
    c.args(["--exact", "cancellation_fixture_child", "--nocapture"])
        .env("XTASK_CANCELLATION_FIXTURE_DIR", work.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = ChildGuard(c.spawn()?);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !work.path().join("ready").exists() {
        ensure(
            Instant::now() < deadline && child.0.try_wait()?.is_none(),
            "Cancellation fixture did not start",
        )?;
        thread::sleep(Duration::from_millis(20));
    }
    let pid = rustix::process::Pid::from_raw(child.0.id() as i32).ok_or("Invalid child PID")?;
    rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure(status.success(), "Cancellation fixture failed")?;
            break;
        }
        ensure(
            Instant::now() < deadline,
            "Cancellation did not terminate promptly",
        )?;
        thread::sleep(Duration::from_millis(20));
    }
    ensure(
        fs::read(work.path().join("cleaned"))? == b"complete",
        "Cancellation skipped cleanup",
    )
}
