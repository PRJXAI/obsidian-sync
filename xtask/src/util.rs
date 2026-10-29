use crate::{Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const JSON_LIMIT: u64 = 64 * 1024 * 1024;
pub const STRUCTURAL_LIMIT: usize = 2_000_000;
static CANCELLED: OnceLock<Arc<AtomicBool>> = OnceLock::new();
pub fn install_cancellation() -> Result {
    let flag = CANCELLED.get_or_init(|| Arc::new(AtomicBool::new(false)));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, flag.clone())?;
    }
    Ok(())
}
pub fn check_cancelled() -> Result {
    if CANCELLED.get().is_some_and(|v| v.load(Ordering::Relaxed)) {
        return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "Task canceled").into());
    }
    Ok(())
}
pub fn cmd(program: &str, args: &[&str], root: &Path) -> Command {
    let mut c = Command::new(program);
    c.args(args).current_dir(root);
    c
}
pub fn bounded_file(path: &Path, limit: u64) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let before = f.metadata()?;
    ensure(
        before.is_file() && before.len() <= limit,
        "Input must be a bounded regular file",
    )?;
    Ok(f)
}
pub fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut f = bounded_file(path, limit)?;
    let before = f.metadata()?;
    let mut bytes = Vec::new();
    (&mut f).take(limit + 1).read_to_end(&mut bytes)?;
    ensure(
        bytes.len() as u64 == before.len() && bytes.len() as u64 <= limit,
        "Input changed size or exceeded its bound",
    )?;
    Ok(bytes)
}
pub fn json(path: &Path) -> Result<Value> {
    strict_json(&read(path, JSON_LIMIT)?)
}
pub fn strict_json(bytes: &[u8]) -> Result<Value> {
    let (mut quoted, mut escaped, mut tokens) = (false, false, 0usize);
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'\"' {
                quoted = false;
            }
        } else if *byte == b'\"' {
            quoted = true;
        } else if b"{}[]:,".contains(byte) {
            tokens += 1;
        }
        ensure(
            tokens <= STRUCTURAL_LIMIT,
            "Evidence exceeds structural allocation budget",
        )?;
    }
    let value: UniqueValue = serde_json::from_slice(bytes)?;
    Ok(value.0)
}
struct UniqueValue(Value);
impl<'de> serde::Deserialize<'de> for UniqueValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON with unique keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Number(
                    serde_json::Number::from_f64(v)
                        .ok_or_else(|| E::custom("Non-finite number"))?,
                )))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<UniqueValue, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<UniqueValue, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<UniqueValue, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("Duplicate evidence key"));
                    }
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn hash(path: &Path) -> Result<String> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    let before = f.metadata()?;
    ensure(
        before.is_file() && before.len() <= 8 * 1024 * 1024 * 1024,
        "Invalid archive",
    )?;
    let mut h = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        h.update(&buffer[..n]);
    }
    let after = f.metadata()?;
    ensure(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "Archive changed during hashing",
    )?;
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}
pub fn write_json(path: &Path, value: &Value) -> Result {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut data = serde_json::to_vec_pretty(value)?;
    data.push(b'\n');
    fs::write(path, data)?;
    Ok(())
}
// Output is held in private temporary files, not unbounded pipes. Secret-bearing
// command output is returned only to its caller; errors never echo raw output.
pub fn output(c: &mut Command, seconds: u64) -> Result<Vec<u8>> {
    let captured = capture(c, seconds)?;
    ensure(
        captured.success,
        "External command failed (raw output withheld)",
    )?;
    Ok(captured.stdout)
}
pub struct Captured {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
pub fn capture(c: &mut Command, seconds: u64) -> Result<Captured> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    c.stdout(stdout.try_clone()?).stderr(stderr.try_clone()?);
    let status = wait_bounded(c, seconds, Some((&stdout, &stderr)), true)?;
    stdout.seek(SeekFrom::Start(0))?;
    stderr.seek(SeekFrom::Start(0))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    stdout.take(JSON_LIMIT + 1).read_to_end(&mut out)?;
    stderr.take(JSON_LIMIT + 1).read_to_end(&mut err)?;
    ensure(
        out.len() as u64 <= JSON_LIMIT && err.len() as u64 <= JSON_LIMIT,
        "Oversized command output",
    )?;
    Ok(Captured {
        success: status.success(),
        stdout: out,
        stderr: err,
    })
}
pub fn logged(c: &mut Command, path: &Path, seconds: u64) -> Result {
    let result = capture(c, seconds)?;
    if path.symlink_metadata().is_ok() {
        fs::remove_file(path)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut file, &result.stdout)?;
    std::io::Write::write_all(&mut file, &result.stderr)?;
    ensure(
        result.success,
        "External scanner failed; raw output retained privately",
    )
}
pub fn text(c: &mut Command, seconds: u64) -> Result<String> {
    Ok(String::from_utf8(output(c, seconds)?)?.trim().into())
}
pub fn run(c: &mut Command, seconds: u64) -> Result {
    ensure(wait(c, seconds)?.success(), "External gate failed")
}
pub fn quiet(c: &mut Command, seconds: u64) -> Result {
    c.stdout(Stdio::null()).stderr(Stdio::null());
    run(c, seconds)
}
pub fn wait(c: &mut Command, seconds: u64) -> Result<std::process::ExitStatus> {
    wait_bounded(c, seconds, None, true)
}
pub fn cleanup(c: &mut Command, seconds: u64) -> Result {
    c.stdout(Stdio::null()).stderr(Stdio::null());
    ensure(
        wait_bounded(c, seconds, None, false)?.success(),
        "Cleanup failed",
    )
}
fn wait_bounded(
    c: &mut Command,
    seconds: u64,
    files: Option<(&File, &File)>,
    interruptible: bool,
) -> Result<std::process::ExitStatus> {
    c.process_group(0);
    let child = c.spawn()?;
    let mut guard = ChildGuard(Some(child));
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if interruptible {
            check_cancelled()?;
        }
        let oversized = if let Some((out, err)) = files {
            out.metadata()?.len() > JSON_LIMIT || err.metadata()?.len() > JSON_LIMIT
        } else {
            false
        };
        if oversized || Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "External command timed out or exceeded output budget",
            )
            .into());
        }
        if let Some(status) = guard.0.as_mut().ok_or("Missing child")?.try_wait()? {
            guard.0.take();
            return Ok(status);
        }
        thread::sleep(Duration::from_millis(50));
    }
}
struct ChildGuard(Option<std::process::Child>);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            // The unreaped leader pins the PID while its owned group is fenced.
            if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
pub fn tracked(root: &Path) -> Result<Vec<PathBuf>> {
    let bytes = output(
        &mut cmd(
            "git",
            &[
                "ls-files",
                "--cached",
                "--others",
                "--exclude-standard",
                "-z",
            ],
            root,
        ),
        30,
    )?;
    let mut paths = bytes
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|b| Ok(PathBuf::from(std::str::from_utf8(b)?)))
        .collect::<Result<Vec<_>>>()?;
    paths.sort();
    paths.dedup();
    for p in &paths {
        ensure(
            !p.is_absolute()
                && p.components()
                    .all(|c| matches!(c, std::path::Component::Normal(_))),
            "Escaping source path",
        )?;
    }
    Ok(paths)
}
pub fn regular_source(root: &Path, relative: &Path) -> Result<PathBuf> {
    let mut p = root.to_path_buf();
    for part in relative.components() {
        ensure(
            matches!(part, std::path::Component::Normal(_)),
            "Escaping source path",
        )?;
        p.push(part);
        ensure(
            !fs::symlink_metadata(&p)?.file_type().is_symlink(),
            "Source symlink rejected",
        )?;
    }
    ensure(p.is_file(), "Source is not a file")?;
    Ok(p)
}
pub fn random_hex() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
pub fn local_docker(root: &Path) -> Result {
    local_docker_endpoint(root).map(|_| ())
}
pub(crate) fn local_docker_endpoint(root: &Path) -> Result<String> {
    let explicit_host = if std::env::var("DOCKER_CONTEXT").is_ok_and(|v| !v.is_empty()) {
        None
    } else {
        std::env::var("DOCKER_HOST").ok()
    };
    let endpoint = if let Some(host) = explicit_host {
        host
    } else {
        text(
            &mut cmd(
                "docker",
                &[
                    "context",
                    "inspect",
                    "--format",
                    "{{.Endpoints.docker.Host}}",
                ],
                root,
            ),
            30,
        )?
    };
    ensure(
        endpoint.starts_with("unix:///"),
        "Disposable fixtures require a local Unix-socket Docker daemon",
    )?;
    Ok(endpoint)
}
pub struct Container {
    pub name: String,
    pub root: PathBuf,
    cleanup_enabled: bool,
}
impl Container {
    pub fn new(root: &Path, prefix: &str) -> Self {
        Self {
            name: format!("{prefix}-{}", &random_hex()[..16]),
            root: root.into(),
            cleanup_enabled: true,
        }
    }
    pub fn inert(root: &Path, prefix: &str) -> Self {
        let mut guard = Self::new(root, prefix);
        guard.cleanup_enabled = false;
        guard
    }
}
impl Drop for Container {
    fn drop(&mut self) {
        if !self.cleanup_enabled {
            return;
        }
        let _ = cleanup(
            &mut cmd("docker", &["rm", "--force", &self.name], &self.root),
            30,
        );
    }
}
pub fn uid_gid() -> String {
    format!(
        "{}:{}",
        rustix::process::getuid().as_raw(),
        rustix::process::getgid().as_raw()
    )
}
pub fn copy_public_sources(root: &Path, destination: &Path) -> Result<usize> {
    let mut count = 0;
    for relative in tracked(root)? {
        if root
            .join(&relative)
            .symlink_metadata()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        {
            continue;
        }
        let source = regular_source(root, &relative)?;
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().expect("parent"))?;
        fs::copy(source, target)?;
        count += 1;
    }
    ensure(count > 0, "Refusing empty source scan")?;
    Ok(count)
}
