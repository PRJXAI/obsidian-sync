use crate::{Result, ensure, security, util};
use base64::Engine;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    net::TcpListener,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub const COUCHDB: &str =
    "couchdb:3.5.3@sha256:4e8e0a366208a87d5059b0f4fcbefff13c32401a655d4629c19be6288ea77675";
pub fn http() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(2))
        .build()?)
}
pub fn port() -> Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}
pub fn wait_http(url: &str, expected: Option<u16>, seconds: u64) -> Result {
    let client = http()?;
    let end = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < end {
        util::check_cancelled()?;
        if let Ok(response) = client.get(url).send()
            && expected.is_none_or(|n| response.status().as_u16() == n)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err("Disposable fixture readiness timed out".into())
}
pub fn config(source: &str, work: &Path, port: u16, image: bool, s3: bool) -> Result<String> {
    let mut value: toml::Value = toml::from_str(source)?;
    if s3 {
        let storage = value.get("storage").ok_or("Missing storage")?;
        ensure(
            storage.get("kind").and_then(toml::Value::as_str) == Some("s3"),
            "Expected disposable S3 configuration",
        )?;
        let endpoint_text = storage
            .get("endpoint")
            .and_then(toml::Value::as_str)
            .ok_or("Missing endpoint")?;
        let endpoint = reqwest::Url::parse(endpoint_text)?;
        ensure(
            endpoint.scheme() == "http"
                && endpoint_text
                    .strip_prefix("http://")
                    .and_then(|v| v.split(['/', '?', '#']).next())
                    .and_then(|v| v.split(':').next())
                    == Some("127.0.0.1")
                && endpoint.host_str() == Some("127.0.0.1")
                && endpoint.username().is_empty()
                && endpoint.password().is_none(),
            "Only literal-loopback disposable S3 is permitted",
        )?;
    }
    let data = if image {
        PathBuf::from("/data")
    } else {
        work.into()
    };
    let table = value.as_table_mut().ok_or("Expected configuration table")?;
    table.insert(
        "listen".into(),
        toml::Value::String(if image {
            "0.0.0.0:8080".into()
        } else {
            format!("127.0.0.1:{port}")
        }),
    );
    table.insert(
        "metadata_dir".into(),
        toml::Value::String(data.join("metadata").to_string_lossy().into()),
    );
    if !s3 {
        table
            .get_mut("storage")
            .and_then(toml::Value::as_table_mut)
            .ok_or("Missing storage table")?
            .insert(
                "root".into(),
                toml::Value::String(data.join("blobs").to_string_lossy().into()),
            );
    }
    table
        .entry("http")
        .or_insert_with(|| toml::Value::Table(Default::default()))
        .as_table_mut()
        .ok_or("Invalid HTTP table")?
        .insert("burst".into(), toml::Value::Integer(1024));
    Ok(toml::to_string_pretty(&value)?)
}
struct Server {
    root: PathBuf,
    work: PathBuf,
    config: PathBuf,
    image: Option<String>,
    benchmark: bool,
    container: util::Container,
    process: Option<Child>,
    running: bool,
    port: u16,
}
impl Server {
    fn command(&self, daemon: bool) -> Command {
        if let Some(image) = &self.image {
            let mut c = util::cmd("docker", &["run"], &self.root);
            if daemon {
                c.args([
                    "-d",
                    "--name",
                    &self.container.name,
                    "--log-driver",
                    "local",
                    "--memory",
                    "2g",
                    "--cpus",
                    "2",
                    "--publish",
                    &format!("127.0.0.1:{}:8080", self.port),
                ]);
            } else {
                c.args(["--rm", "--network", "none", "--log-driver", "none"]);
            }
            c.args([
                "--read-only",
                "--user",
                "65532:65532",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--mount",
                &format!("type=bind,source={}/data,target=/data", self.work.display()),
                "--mount",
                &format!(
                    "type=bind,source={},target=/config/test.toml,readonly",
                    self.config.display()
                ),
                image,
                "--config",
                "/config/test.toml",
            ]);
            c
        } else {
            let mut c = Command::new(
                self.root
                    .join("target")
                    .join(if self.benchmark { "release" } else { "debug" })
                    .join("obsidian-sync-server"),
            );
            c.current_dir(&self.root).arg("--config").arg(&self.config);
            c
        }
    }
    fn admin(&self, args: &[&str]) -> Result<String> {
        let mut c = self.command(false);
        c.args(args);
        util::text(&mut c, 60)
    }
    fn issue(&self, vault: &str, bootstrap: bool) -> Result<BTreeMap<String, String>> {
        let mut args = vec!["issue", "--vault", vault];
        if bootstrap {
            args.push("--allow-database-reset");
        }
        let data = self.admin(&args)?;
        let values = data
            .lines()
            .map(|line| {
                line.split_once('=')
                    .map(|(a, b)| (a.into(), b.into()))
                    .ok_or_else(|| "Invalid issue output".into())
            })
            .collect::<Result<BTreeMap<String, String>>>()?;
        ensure(
            values.contains_key("principal") && values.contains_key("token"),
            "Missing issued credentials",
        )?;
        Ok(values)
    }
    fn start(&mut self) -> Result {
        let mut c = self.command(true);
        c.arg("serve");
        if self.image.is_some() {
            util::quiet(&mut c, 60)?;
            self.running = true;
        } else {
            let log = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.work.join("server.log"))?;
            c.stdout(log.try_clone()?).stderr(log);
            self.process = Some(c.spawn()?);
        }
        wait_http(
            &format!("http://127.0.0.1:{}/health/ready", self.port),
            Some(204),
            30,
        )
    }
    fn stop(&mut self) -> Result {
        if self.image.is_some() && self.running {
            util::quiet(
                &mut util::cmd(
                    "docker",
                    &["stop", "--time", "35", &self.container.name],
                    &self.root,
                ),
                45,
            )?;
            let state: Value = serde_json::from_slice(&util::output(
                &mut util::cmd(
                    "docker",
                    &[
                        "inspect",
                        "--format",
                        "{{json .State}}",
                        &self.container.name,
                    ],
                    &self.root,
                ),
                15,
            )?)?;
            util::quiet(
                &mut util::cmd("docker", &["rm", &self.container.name], &self.root),
                15,
            )?;
            self.running = false;
            ensure(
                state["Running"] == false && state["ExitCode"] == 0,
                "Unclean disposable container shutdown",
            )?;
        }
        if let Some(child) = self.process.as_mut() {
            if child.try_wait()?.is_none() {
                let pid = rustix::process::Pid::from_raw(child.id() as i32).ok_or("Invalid PID")?;
                rustix::process::kill_process(pid, rustix::process::Signal::TERM)?;
            }
            let deadline = Instant::now() + Duration::from_secs(35);
            loop {
                if let Some(status) = child.try_wait()? {
                    self.process.take();
                    ensure(status.success(), "Unclean disposable server shutdown")?;
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.process.take();
                    return Err("Disposable server shutdown timed out".into());
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.stop();
        if let Some(mut child) = self.process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.image.is_some() {
            let _ = util::cleanup(
                &mut util::cmd(
                    "docker",
                    &["rm", "--force", &self.container.name],
                    &self.root,
                ),
                30,
            );
            let _ = util::cleanup(
                &mut util::cmd(
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
                        &format!("{}/data:/data", self.work.display()),
                        "--entrypoint",
                        "rm",
                        security::HELPER,
                        "-rf",
                        "/data/metadata",
                        "/data/blobs",
                    ],
                    &self.root,
                ),
                60,
            );
        }
    }
}
fn node(
    root: &Path,
    file: &str,
    env: &BTreeMap<String, String>,
    phase: Option<&str>,
    seconds: u64,
) -> Result {
    let mut c = util::cmd("node", &[file], root);
    c.envs(env);
    if let Some(phase) = phase {
        c.env("LS_TEST_PHASE", phase);
    }
    util::run(&mut c, seconds)
}
pub fn livesync(
    root: &Path,
    storage: Option<&Path>,
    image: Option<&str>,
    benchmark: bool,
) -> Result {
    ensure(
        storage.is_none() || image.is_none(),
        "Storage/image fixture modes conflict",
    )?;
    if image.is_some() {
        util::local_docker(root)?;
    } else {
        let mut c = util::cmd(
            "cargo",
            &["build", "--locked", "-p", "obsidian-sync-server"],
            root,
        );
        if benchmark {
            c.arg("--release");
        }
        util::run(&mut c, 900)?;
    }
    util::run(
        &mut util::cmd(
            "npm",
            &[
                "ci",
                "--prefix",
                "tests/compat",
                "--ignore-scripts",
                "--no-fund",
            ],
            root,
        ),
        180,
    )?;
    fs::create_dir_all(root.join(".work"))?;
    let temporary = tempfile::Builder::new()
        .prefix("livesync-")
        .tempdir_in(root.join(".work"))?;
    let work = temporary.path().canonicalize()?;
    let port = port()?;
    let source = String::from_utf8(util::read(
        storage.unwrap_or(&root.join("config/filesystem.toml")),
        65536,
    )?)?;
    let path = work.join("config.toml");
    fs::write(
        &path,
        config(&source, &work, port, image.is_some(), storage.is_some())?,
    )?;
    if image.is_some() {
        fs::create_dir(work.join("data"))?;
        fs::set_permissions(work.join("data"), fs::Permissions::from_mode(0o777))?;
    }
    let mut server = Server {
        root: root.into(),
        work: work.clone(),
        config: path,
        image: image.map(String::from),
        benchmark,
        container: if image.is_some() {
            util::Container::new(root, "livesync-fixture")
        } else {
            util::Container::inert(root, "livesync-fixture")
        },
        process: None,
        running: false,
        port,
    };
    let vault = server.admin(&["create-database", "--name", "vault"])?;
    let encrypted = server.admin(&["create-database", "--name", "encrypted"])?;
    let bootstrap = server.admin(&["create-database", "--name", "bootstrap"])?;
    let issued = server.issue(&vault, false)?;
    let peer = server.issue(&vault, false)?;
    let encrypted = server.issue(&encrypted, false)?;
    let bootstrap = server.issue(&bootstrap, true)?;
    let mut env = BTreeMap::from([
        ("LS_TEST_URL".into(), format!("http://127.0.0.1:{port}")),
        ("LS_TEST_USER".into(), issued["principal"].clone()),
        ("LS_TEST_TOKEN".into(), issued["token"].clone()),
        ("LS_TEST_PEER_USER".into(), peer["principal"].clone()),
        ("LS_TEST_PEER_TOKEN".into(), peer["token"].clone()),
        (
            "LS_TEST_ENCRYPTED_USER".into(),
            encrypted["principal"].clone(),
        ),
        ("LS_TEST_ENCRYPTED_TOKEN".into(), encrypted["token"].clone()),
        (
            "LS_TEST_BOOTSTRAP_USER".into(),
            bootstrap["principal"].clone(),
        ),
        ("LS_TEST_BOOTSTRAP_TOKEN".into(), bootstrap["token"].clone()),
        ("LS_TEST_E2EE_PASSPHRASE".into(), util::random_hex()),
        (
            "LS_TEST_STATE".into(),
            work.join("restart.json").to_string_lossy().into(),
        ),
    ]);
    if benchmark {
        env.insert(
            "LS_TEST_BENCHMARK_KEYS".into(),
            serde_json::to_string(
                &(0..8)
                    .map(|_| server.issue(&vault, false))
                    .collect::<Result<Vec<_>>>()?,
            )?,
        );
    }
    server.start()?;
    if benchmark {
        let finished = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(0));
        let count = Arc::new(AtomicU64::new(0));
        let (done, p, n) = (finished.clone(), peak.clone(), count.clone());
        let pid = server.process.as_ref().map(Child::id);
        let name = server.container.name.clone();
        let root_clone = root.to_path_buf();
        let sampler = thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let bytes = if let Some(pid) = pid {
                    util::text(
                        &mut util::cmd("ps", &["-o", "rss=", "-p", &pid.to_string()], &root_clone),
                        5,
                    )
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|v| v * 1024)
                } else {
                    util::text(
                        &mut util::cmd(
                            "docker",
                            &["stats", "--no-stream", "--format", "{{.MemUsage}}", &name],
                            &root_clone,
                        ),
                        5,
                    )
                    .ok()
                    .and_then(|v| memory_bytes(&v))
                };
                if let Some(bytes) = bytes {
                    p.fetch_max(bytes, Ordering::Relaxed);
                    n.fetch_add(1, Ordering::Relaxed);
                } else {
                    break;
                }
                thread::sleep(Duration::from_millis(100));
            }
        });
        let result = node(root, "tests/compat/benchmark.mjs", &env, None, 180);
        finished.store(true, Ordering::Relaxed);
        sampler.join().map_err(|_| "Memory sampler panicked")?;
        result?;
        ensure(
            count.load(Ordering::Relaxed) > 0,
            "No memory samples collected",
        )?;
        println!(
            "{}",
            json!({if image.is_some(){"sampled_peak_container_memory_bytes"}else{"sampled_peak_server_rss_bytes"}:peak.load(Ordering::Relaxed),"memory_samples":count.load(Ordering::Relaxed)})
        );
    } else {
        node(
            root,
            "tests/compat/livesync.mjs",
            &env,
            Some("initial"),
            180,
        )?;
        server.stop()?;
        server.start()?;
        node(root, "tests/compat/livesync.mjs", &env, Some("restart"), 90)?;
    }
    server.stop()?;
    println!(
        "PASS: actual Commonlib/PouchDB disposable client fixture{}",
        if benchmark {
            " benchmark"
        } else {
            " with restart"
        }
    );
    Ok(())
}
pub fn memory_bytes(value: &str) -> Option<u64> {
    let m = regex::Regex::new(r"^([0-9.]+)(B|KiB|MiB|GiB)")
        .ok()?
        .captures(value)?;
    let factor = match &m[2] {
        "B" => 1.,
        "KiB" => 1024.,
        "MiB" => 1024. * 1024.,
        "GiB" => 1024. * 1024. * 1024.,
        _ => return None,
    };
    Some((m[1].parse::<f64>().ok()? * factor) as u64)
}
pub fn reference(root: &Path) -> Result {
    util::local_docker(root)?;
    util::run(
        &mut util::cmd(
            "npm",
            &[
                "ci",
                "--prefix",
                "tests/compat",
                "--ignore-scripts",
                "--no-fund",
            ],
            root,
        ),
        180,
    )?;
    let container = util::Container::new(root, "obsidian-sync-reference");
    let username = "fixture-user";
    let password = util::random_hex();
    let mut c = util::cmd(
        "docker",
        &[
            "run",
            "--rm",
            "-d",
            "--name",
            &container.name,
            "--env",
            "COUCHDB_USER",
            "--env",
            "COUCHDB_PASSWORD",
            "--publish",
            "127.0.0.1::5984",
            "--tmpfs",
            "/opt/couchdb/data:uid=5984,gid=5984,mode=0700",
            COUCHDB,
        ],
        root,
    );
    c.env("COUCHDB_USER", username)
        .env("COUCHDB_PASSWORD", &password);
    util::quiet(&mut c, 120)?;
    let binding = util::text(
        &mut util::cmd("docker", &["port", &container.name, "5984"], root),
        30,
    )?;
    let port = binding
        .rsplit(':')
        .next()
        .ok_or("Missing port")?
        .parse::<u16>()?;
    let url = format!("http://127.0.0.1:{port}");
    let client = http()?;
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    );
    let mut ready = false;
    for _ in 0..120 {
        util::check_cancelled()?;
        if client
            .get(&url)
            .header("Authorization", &auth)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    ensure(ready, "Reference CouchDB did not start")?;
    for (path, body) in [
        ("/_node/_local/_config/cluster/n", Some(json!("1"))),
        ("/vault?n=1", None),
        ("/encrypted?n=1", None),
        ("/bootstrap?n=1", None),
    ] {
        let mut request = client
            .put(format!("{url}{path}"))
            .header("Authorization", &auth)
            .timeout(Duration::from_secs(30));
        if let Some(body) = body {
            request = request.json(&body);
        }
        ensure(
            request.send()?.status().is_success(),
            "Reference CouchDB provisioning failed",
        )?;
    }
    let work = tempfile::tempdir()?;
    let env = BTreeMap::from([
        ("LS_TEST_URL".into(), url),
        ("LS_TEST_USER".into(), username.into()),
        ("LS_TEST_TOKEN".into(), password.clone()),
        ("LS_TEST_ENCRYPTED_USER".into(), username.into()),
        ("LS_TEST_ENCRYPTED_TOKEN".into(), password.clone()),
        ("LS_TEST_BOOTSTRAP_USER".into(), username.into()),
        ("LS_TEST_BOOTSTRAP_TOKEN".into(), password),
        ("LS_TEST_E2EE_PASSPHRASE".into(), util::random_hex()),
        (
            "LS_TEST_STATE".into(),
            work.path().join("state.json").to_string_lossy().into(),
        ),
    ]);
    node(root, "tests/compat/livesync.mjs", &env, None, 180)
}
