use crate::{Result, clients, docs, ensure, util};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
#[path = "../tests/fixtures/k3d_cleanup.rs"]
mod k3d_cleanup;
#[cfg(test)]
#[path = "../tests/fixtures/rustfs/native.rs"]
mod rustfs_candidate;

pub const K3S: &str = "rancher/k3s:v1.37.1-k3s1@sha256:ca7f37d993d82ef0dcdcfecb2e0e2618ea541dbaffc620c8cedebe01a82acd0d";
pub const K3D_TOOLS: &str = "ghcr.io/k3d-io/k3d-tools:5.9.0@sha256:c57abce697e66feeb826922718738fe186b47779312d49d4e51e6fb9b8a6f34d";
pub const PAUSE: &str = "registry.k8s.io/pause:3.10.1@sha256:278fb9dbcca9518083ad1e11276933a2e96f23de604a3a08cc3c80002767d24c";
pub fn test_build_context(root: &Path) -> Result {
    util::local_docker(root)?;
    fs::create_dir_all(root.join(".work"))?;
    let work = tempfile::Builder::new()
        .prefix("context-test-")
        .tempdir_in(root.join(".work"))?;
    fs::copy(
        root.join(".dockerignore"),
        work.path().join(".dockerignore"),
    )?;
    let included = [
        "Cargo.toml",
        "config/filesystem.toml",
        "xtask/Cargo.toml",
        "xtask/src/lib.rs",
        "xtask/src/accepted-risks.json",
        "xtask/tests/support/mod.rs",
        "xtask/tests/fixtures/k3d_cleanup.rs",
        "xtask/tests/fixtures/k3d_control.rs",
        "xtask/tests/fixtures/rustfs/native.rs",
        "xtask/tests/fixtures/rustfs/Dockerfile",
        ".cargo/config.toml",
    ];
    for path in included {
        let target = work.path().join(path);
        fs::create_dir_all(target.parent().ok_or("Missing context parent")?)?;
        fs::write(target, "public synthetic fixture")?;
    }
    let excluded = [
        ".env",
        "config/private-canary.toml",
        ".cargo/credentials.toml",
        "data/private-canary",
        "tests/compat/node_modules/private-canary",
        "xtask/private-canary.toml",
        "xtask/src/private-risk-canary.json",
        "xtask/tests/support/private-canary.toml",
        "xtask/tests/support/.env",
        "xtask/tests/fixtures/rustfs/private-canary.toml",
        "xtask/tests/fixtures/rustfs/.env",
        "xtask/tests/fixtures/other/private-canary.rs",
        "xtask/tests/fixtures/k3d_private.rs",
    ];
    for path in excluded {
        let target = work.path().join(path);
        fs::create_dir_all(target.parent().ok_or("Missing canary parent")?)?;
        fs::write(target, "SYNTHETIC_PRIVATE_CONTEXT_CANARY")?;
    }
    let source = fs::read_to_string(root.join("Dockerfile"))?;
    let mut dockerfile = format!(
        "{}\nFROM {}\nCOPY . /context\n",
        source.lines().next().ok_or("Missing frontend")?,
        crate::security::BUILD_IMAGE
    );
    for path in included {
        dockerfile.push_str(&format!("RUN [\"test\",\"-s\",\"/context/{path}\"]\n"));
    }
    for path in excluded {
        dockerfile.push_str(&format!(
            "RUN [\"test\",\"!\",\"-e\",\"/context/{path}\"]\n"
        ));
    }
    fs::write(work.path().join("Dockerfile"), dockerfile)?;
    let tag = format!("obsidian-sync-context-test:{}", &util::random_hex()[..16]);
    struct ImageCleanup<'a> {
        root: &'a Path,
        tag: &'a str,
    }
    impl Drop for ImageCleanup<'_> {
        fn drop(&mut self) {
            let _ = util::cleanup(
                &mut util::cmd("docker", &["image", "rm", self.tag], self.root),
                30,
            );
        }
    }
    let _cleanup = ImageCleanup { root, tag: &tag };
    util::run(
        &mut util::cmd(
            "docker",
            &[
                "build",
                "--network",
                "none",
                "--tag",
                &tag,
                work.path().to_str().ok_or("Invalid context path")?,
            ],
            root,
        ),
        180,
    )?;
    println!("Build context excludes synthetic operator/config/credential/data canaries");
    Ok(())
}
pub fn validate(root: &Path) -> Result {
    docs::sync(root, true)?;
    for overlay in [
        "base",
        "overlays/filesystem",
        "overlays/s3",
        "overlays/gcs",
        "overlays/azure",
    ] {
        util::quiet(
            &mut util::cmd(
                "kustomize",
                &["build", &format!("deploy/kustomize/{overlay}")],
                root,
            ),
            60,
        )?;
    }
    util::run(
        &mut util::cmd("docker", &["compose", "config", "--quiet"], root),
        60,
    )?;
    util::run(
        util::cmd(
            "docker",
            &[
                "compose",
                "-f",
                "docker-compose.yml",
                "-f",
                "deploy/compose.release.yml",
                "config",
                "--quiet",
            ],
            root,
        )
        .env("SYNC_RELEASE_IMAGE", "obsidian-sync:release-validation")
        .env("SYNC_RELEASE_REVISION", "validation-only"),
        60,
    )?;
    util::run(
        util::cmd(
            "docker",
            &[
                "compose",
                "-f",
                "docker-compose.yml",
                "-f",
                "docker-compose.s3.yml",
                "config",
                "--quiet",
            ],
            root,
        )
        .env("S3_ACCESS_KEY_FILE", "/dev/null")
        .env("S3_SECRET_KEY_FILE", "/dev/null"),
        60,
    )?;
    util::run(
        util::cmd(
            "docker",
            &[
                "compose",
                "-f",
                "docker-compose.test-s3.yml",
                "config",
                "--quiet",
            ],
            root,
        )
        .env("TEST_S3_ACCESS_KEY", "validation-only")
        .env("TEST_S3_SECRET_KEY", "validation-only"),
        60,
    )?;
    println!("Compose and Kustomize render; API validation is only against disposable k3d");
    Ok(())
}
struct Compose {
    root: PathBuf,
    project: String,
    file: PathBuf,
    env: Vec<(String, String)>,
}
impl Compose {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = util::cmd(
            "docker",
            &["compose", "-p", &self.project, "-f"],
            &self.root,
        );
        c.arg(&self.file)
            .args(args)
            .envs(self.env.iter().map(|(k, v)| (k, v)));
        c
    }
}
impl Drop for Compose {
    fn drop(&mut self) {
        let _ = util::cleanup(&mut self.command(&["down", "-v"]), 90);
    }
}
pub fn s3(root: &Path) -> Result {
    s3_fixture(root, "docker-compose.test-s3.yml".into())
}
// The fixed, ignored RustFS evaluation reuses every storage/client control.
// This is not a caller-selectable image or CLI override.
fn s3_fixture(root: &Path, file: PathBuf) -> Result {
    util::local_docker(root)?;
    fs::create_dir_all(root.join(".work"))?;
    let work = tempfile::Builder::new()
        .prefix("s3-")
        .tempdir_in(root.join(".work"))?;
    let path = work.path().canonicalize()?;
    let access = util::random_hex();
    let secret = util::random_hex();
    // Credentials are synthetic, unique per disposable service; never printed.
    for (name, value) in [("access", &access), ("secret", &secret)] {
        let target = path.join(name);
        fs::write(&target, value)?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o600))?;
    }
    let compose = Compose {
        root: root.into(),
        project: format!("obsidian-sync-test-{}", &util::random_hex()[..12]),
        file,
        env: vec![
            ("TEST_S3_ACCESS_KEY".into(), access),
            ("TEST_S3_SECRET_KEY".into(), secret),
        ],
    };
    util::run(&mut compose.command(&["up", "-d"]), 120)?;
    let binding = util::text(&mut compose.command(&["port", "object-store", "9000"]), 30)?;
    let port = binding
        .rsplit(':')
        .next()
        .ok_or("Missing port")?
        .parse::<u16>()?;
    clients::wait_http(&format!("http://127.0.0.1:{port}/"), None, 120)?;
    let mut config: toml::Value =
        toml::from_str(&fs::read_to_string(root.join("config/s3.toml"))?)?;
    config["metadata_dir"] = toml::Value::String(path.join("metadata").to_string_lossy().into());
    config["storage"]["endpoint"] = toml::Value::String(format!("http://127.0.0.1:{port}"));
    config
        .get_mut("storage")
        .and_then(toml::Value::as_table_mut)
        .ok_or("Missing storage table")?
        .insert("allow_insecure_loopback".into(), toml::Value::Boolean(true));
    let config_path = path.join("config.toml");
    fs::write(&config_path, toml::to_string_pretty(&config)?)?;
    let env = [
        (
            "SYNC_S3_TEST_CONFIG",
            config_path.to_string_lossy().into_owned(),
        ),
        (
            "S3_ACCESS_KEY_FILE",
            path.join("access").to_string_lossy().into_owned(),
        ),
        (
            "S3_SECRET_KEY_FILE",
            path.join("secret").to_string_lossy().into_owned(),
        ),
        ("SYNC_S3_CREATE_BUCKET", "yes".into()),
    ];
    util::run(
        util::cmd(
            "cargo",
            &[
                "test",
                "--locked",
                "-p",
                "obsidian-sync-server",
                "--test",
                "storage_contract",
                "s3_contract",
                "--",
                "--ignored",
                "--exact",
            ],
            root,
        )
        .envs(env.iter().map(|(k, v)| (k, v))),
        600,
    )?;
    // Keep credential scope on the child invocation, not process-global env.
    util::run(
        util::cmd(
            "cargo",
            &[
                "xtask",
                "test-livesync",
                "--storage-config",
                config_path.to_str().ok_or("Invalid config path")?,
            ],
            root,
        )
        .envs(env.iter().map(|(k, v)| (k, v))),
        900,
    )
}
struct DataCleanup {
    root: PathBuf,
    data: PathBuf,
}
impl Drop for DataCleanup {
    fn drop(&mut self) {
        let _ = util::cleanup(
            &mut util::cmd(
                "docker",
                &[
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    "--read-only",
                    "--user",
                    "65532:65532",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--volume",
                    &format!("{}:/data", self.data.display()),
                    "--entrypoint",
                    "rm",
                    crate::security::BUILD_IMAGE,
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
pub fn writer_denied(result: &util::Captured) -> bool {
    !result.success
        && [&result.stdout, &result.stderr]
            .iter()
            .any(|bytes| String::from_utf8_lossy(bytes).contains("another writer owns"))
}
pub fn compose(root: &Path) -> Result {
    util::local_docker(root)?;
    fs::create_dir_all(root.join(".work"))?;
    let work = tempfile::Builder::new()
        .prefix("compose-")
        .tempdir_in(root.join(".work"))?;
    let path = work.path().canonicalize()?;
    let data = path.join("data");
    fs::create_dir(&data)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o777))?;
    let _cleanup = DataCleanup {
        root: root.into(),
        data: data.clone(),
    };
    let port = clients::port()?;
    let compose = Compose {
        root: root.into(),
        project: format!("obsidian-sync-smoke-{}", &util::random_hex()[..12]),
        file: "docker-compose.yml".into(),
        env: vec![
            ("SYNC_DATA_DIR".into(), data.to_string_lossy().into()),
            ("SYNC_CONFIG_FILE".into(), "./config/filesystem.toml".into()),
            ("SYNC_PORT".into(), port.to_string()),
        ],
    };
    util::run(&mut compose.command(&["up", "-d", "--no-build"]), 120)?;
    for endpoint in ["live", "ready"] {
        clients::wait_http(
            &format!("http://127.0.0.1:{port}/health/{endpoint}"),
            Some(204),
            60,
        )?;
    }
    let second = util::capture(
        &mut compose.command(&["exec", "-T", "server", "/server", "create-vault"]),
        30,
    )?;
    ensure(writer_denied(&second), "Compose writer fencing failed")?;
    util::run(&mut compose.command(&["stop", "-t", "35"]), 45)?;
    util::quiet(
        &mut compose.command(&["run", "--rm", "--no-deps", "server", "create-vault"]),
        60,
    )?;
    println!(
        "Compose smoke passed: private probes, writer exclusion, graceful stop and persistent restart"
    );
    Ok(())
}
pub struct Cluster {
    pub root: PathBuf,
    pub name: String,
    pub kubeconfig: PathBuf,
    endpoint: String,
    armed: bool,
}
pub fn k3d_config(name: &str, data: &str, port: u16) -> Result<serde_json::Value> {
    ensure(
        name.starts_with("sync-smoke-")
            && name.len() <= 32
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && data == format!("k3d-{name}-data")
            && port > 0,
        "Invalid disposable cluster configuration",
    )?;
    let args = [
        "--disable=coredns,traefik,servicelb,metrics-server,local-storage".to_owned(),
        "--disable-helm-controller".to_owned(),
        format!("--pause-image={PAUSE}"),
    ]
    .map(|arg| serde_json::json!({"arg":arg,"nodeFilters":["server:0"]}));
    Ok(serde_json::json!({
        "apiVersion":"k3d.io/v1alpha5","kind":"Simple","metadata":{"name":name},
        "servers":1,"agents":0,"image":K3S,
        "kubeAPI":{"host":"127.0.0.1","hostIP":"127.0.0.1","hostPort":port.to_string()},
        "volumes":[{"volume":format!("{data}:/var/lib/sync-smoke"),"nodeFilters":["server:0"]}],
        "options":{
            "kubeconfig":{"updateDefaultKubeconfig":false,"switchCurrentContext":false},
            "runtime":{"serversMemory":"4g","hostPidMode":false},
            "k3d":{"wait":true,"timeout":"120s","disableLoadbalancer":true},
            "k3s":{"extraArgs":args}
        }
    }))
}
pub fn private_kubeconfig(value: &serde_json::Value, name: &str, port: u16) -> Result {
    let context = format!("k3d-{name}");
    ensure(
        value["current-context"] == context,
        "Unexpected disposable context",
    )?;
    for field in ["clusters", "contexts", "users"] {
        ensure(
            value[field].as_array().is_some_and(|a| a.len() == 1),
            "Unexpected kubeconfig members",
        )?;
    }
    let cluster = &value["clusters"][0]["cluster"];
    let user = &value["users"][0]["user"];
    ensure(
        cluster["server"] == format!("https://127.0.0.1:{port}")
            && cluster["certificate-authority-data"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
            && value["clusters"][0]["name"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
            && value["users"][0]["name"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
            && cluster.as_object().is_some_and(|m| {
                m.keys()
                    .all(|k| ["server", "certificate-authority-data"].contains(&k.as_str()))
            })
            && user["client-certificate-data"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
            && user["client-key-data"]
                .as_str()
                .is_some_and(|v| !v.is_empty())
            && user.as_object().is_some_and(|m| {
                m.keys()
                    .all(|k| ["client-certificate-data", "client-key-data"].contains(&k.as_str()))
            })
            && value["contexts"][0]["name"] == context
            && value["contexts"][0]["context"]["cluster"] == value["clusters"][0]["name"]
            && value["contexts"][0]["context"]["user"] == value["users"][0]["name"],
        "Kubeconfig is not an isolated loopback certificate fixture",
    )
}
pub fn fenced_command(root: &Path, kubeconfig: &Path, program: &str, args: &[&str]) -> Command {
    let mut c = util::cmd(program, &[], root);
    if program == "kubectl" {
        c.arg("--kubeconfig").arg(kubeconfig);
    }
    c.env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", kubeconfig.parent().unwrap_or(root))
        .env("KUBECONFIG", kubeconfig)
        .args(args);
    c
}
pub fn pod_ready_command(root: &Path, kubeconfig: &Path) -> Command {
    fenced_command(
        root,
        kubeconfig,
        "kubectl",
        &[
            "-n",
            "obsidian-sync",
            "wait",
            "--for=condition=Ready",
            "pod",
            "-l",
            "app=obsidian-sync",
            "--timeout=2s",
        ],
    )
}
impl Cluster {
    fn k3d(&self, args: &[&str]) -> Command {
        let mut c = fenced_command(&self.root, &self.kubeconfig, "k3d", args);
        c.current_dir(self.kubeconfig.parent().unwrap_or(&self.root))
            .env("DOCKER_HOST", &self.endpoint)
            .env(
                "DOCKER_CONFIG",
                self.kubeconfig.parent().unwrap_or(&self.root),
            )
            .env("K3D_IMAGE_TOOLS", K3D_TOOLS);
        c
    }
    fn docker(&self, args: &[&str]) -> Command {
        let mut c = fenced_command(
            &self.root,
            &self.kubeconfig,
            "docker",
            &["--host", &self.endpoint],
        );
        c.env(
            "DOCKER_CONFIG",
            self.kubeconfig.parent().unwrap_or(&self.root),
        )
        .args(args);
        c
    }
    fn remove(&mut self) -> Result {
        if !self.armed {
            return Ok(());
        }
        let deletion = util::cleanup(&mut self.k3d(&["cluster", "delete", &self.name]), 120);
        if deletion.is_err() {
            // Creation may fail before k3d can discover a cluster. These exact
            // names were all absent before arming; never enumerate/delete others.
            for args in [
                vec![
                    "rm".to_owned(),
                    "--force".into(),
                    format!("k3d-{}-server-0", self.name),
                    format!("k3d-{}-tools", self.name),
                ],
                vec!["network".into(), "rm".into(), format!("k3d-{}", self.name)],
                vec![
                    "volume".into(),
                    "rm".into(),
                    format!("k3d-{}-images", self.name),
                ],
            ] {
                let mut c = self.docker(&[]);
                c.args(args);
                let _ = util::cleanup(&mut c, 30);
            }
        }
        // Attempt data-volume removal even after a failed/canceled create or
        // failed k3d deletion; don't leave data merely because no node exists.
        let data = util::cleanup(
            &mut self.docker(&["volume", "rm", &format!("k3d-{}-data", self.name)]),
            30,
        );
        let absence = self.resources_absent(true);
        if absence.is_ok() {
            self.armed = false;
        }
        // Compensation never erases the original failure or authorizes success.
        deletion.and(data).and(absence)
    }
    fn resources_absent(&self, cleanup: bool) -> Result {
        for (args, name) in [
            (vec!["ps", "-aq"], format!("^/k3d-{}-", self.name)),
            (vec!["network", "ls", "-q"], format!("^k3d-{}$", self.name)),
            (vec!["volume", "ls", "-q"], format!("^k3d-{}-", self.name)),
        ] {
            for filter in [
                format!("label=k3d.cluster={}", self.name),
                format!("name={name}"),
            ] {
                let mut c = self.docker(&[]);
                c.args(&args).args(["--filter", &filter]);
                let result = if cleanup {
                    util::cleanup_output(&mut c, 30)?
                } else {
                    util::output(&mut c, 30)?
                };
                ensure(
                    result.iter().all(u8::is_ascii_whitespace),
                    "Refusing pre-existing or residual disposable resources",
                )?;
            }
        }
        Ok(())
    }
    pub fn kubectl(&self, args: &[&str]) -> Command {
        fenced_command(&self.root, &self.kubeconfig, "kubectl", args)
    }
    fn stop_workload(&self) -> Result {
        util::quiet(
            &mut self.kubectl(&[
                "-n",
                "obsidian-sync",
                "scale",
                "deployment/obsidian-sync",
                "--replicas=0",
            ]),
            30,
        )?;
        let end = Instant::now() + Duration::from_secs(90);
        loop {
            let pods = util::strict_json(&util::output(
                &mut self.kubectl(&[
                    "-n",
                    "obsidian-sync",
                    "get",
                    "pods",
                    "-l",
                    "app=obsidian-sync",
                    "-o",
                    "json",
                ]),
                15,
            )?)?;
            if pods["items"].as_array().is_some_and(Vec::is_empty) {
                return Ok(());
            }
            ensure(Instant::now() < end, "Disposable writer did not stop")?;
            thread::sleep(Duration::from_millis(100));
        }
    }
    fn admin(&self, home: &Path, name: &str, args: &[&str]) -> Result<String> {
        let deployment = util::strict_json(&util::output(
            &mut self.kubectl(&[
                "-n",
                "obsidian-sync",
                "get",
                "deployment/obsidian-sync",
                "-o",
                "json",
            ]),
            30,
        )?)?;
        let mut spec = deployment["spec"]["template"]["spec"].clone();
        ensure(
            spec["containers"].as_array().is_some_and(|v| v.len() == 1)
                && spec["containers"][0]["image"] == "obsidian-sync:local",
            "Unexpected disposable admin image",
        )?;
        spec["restartPolicy"] = "Never".into();
        let container = spec["containers"][0]
            .as_object_mut()
            .ok_or("Missing disposable container")?;
        container.insert("args".into(), serde_json::json!(args));
        for field in ["startupProbe", "livenessProbe", "readinessProbe", "ports"] {
            container.remove(field);
        }
        let file = home.join(format!("{name}.json"));
        util::write_json(
            &file,
            &serde_json::json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":name,"namespace":"obsidian-sync"},"spec":spec}),
        )?;
        util::quiet(
            &mut self.kubectl(&[
                "apply",
                "-f",
                file.to_str().ok_or("Invalid admin pod path")?,
            ]),
            30,
        )?;
        let finished = util::quiet(
            &mut self.kubectl(&[
                "-n",
                "obsidian-sync",
                "wait",
                "--for=jsonpath={.status.phase}=Succeeded",
                &format!("pod/{name}"),
                "--timeout=60s",
            ]),
            70,
        );
        let output = util::output(
            &mut self.kubectl(&["-n", "obsidian-sync", "logs", name]),
            30,
        )?;
        fs::write(
            home.join(format!("{name}.log")),
            if args.first() == Some(&"issue") {
                &b"Credential output withheld\n"[..]
            } else {
                &output
            },
        )?;
        finished?;
        util::quiet(
            &mut self.kubectl(&[
                "-n",
                "obsidian-sync",
                "delete",
                "pod",
                name,
                "--wait=true",
                "--timeout=30s",
            ]),
            40,
        )?;
        Ok(String::from_utf8(output)?.trim().into())
    }
    fn wait_ready(&self) -> Result {
        let deadline = Instant::now() + Duration::from_secs(270);
        while Instant::now() < deadline {
            util::check_cancelled()?;
            if util::quiet(&mut pod_ready_command(&self.root, &self.kubeconfig), 10).is_ok() {
                return Ok(());
            }
            thread::sleep(Duration::from_secs(1));
        }
        Err("Disposable pod failed to become Ready".into())
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.remove();
    }
}
struct Forward(Child);
impl Drop for Forward {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub fn kubernetes(root: &Path) -> Result {
    let endpoint = util::local_docker_endpoint(root)?;
    fs::create_dir_all(root.join(".work"))?;
    let work = tempfile::Builder::new()
        .prefix("k3d-smoke-")
        .tempdir_in(root.join(".work"))?;
    let home = work.path().canonicalize()?;
    fs::set_permissions(&home, fs::Permissions::from_mode(0o700))?;

    let mut cluster = Cluster {
        root: root.into(),
        name: format!("sync-smoke-{}", &util::random_hex()[..20]),
        kubeconfig: home.join("kubeconfig"),
        endpoint,
        armed: false,
    };
    let result = (|| -> Result {
        let version = util::text(&mut cluster.k3d(&["version"]), 15)?;
        ensure(
            version.lines().any(|s| s == "k3d version v5.9.0"),
            "Unsupported k3d version",
        )?;
        cluster.resources_absent(false)?;
        cluster.armed = true;
        let data = format!("k3d-{}-data", cluster.name);
        let mut volume = cluster.docker(&[
            "volume",
            "create",
            "--label",
            &format!("k3d.cluster={}", cluster.name),
            &data,
        ]);
        util::quiet(&mut volume, 30)?;
        let api_port = clients::port()?;
        let config = home.join("cluster.json");
        util::write_json(&config, &k3d_config(&cluster.name, &data, api_port)?)?;
        util::logged(
            &mut cluster.k3d(&[
                "cluster",
                "create",
                &cluster.name,
                "--config",
                config.to_str().ok_or("Invalid config")?,
                "--kubeconfig-update-default=false",
                "--kubeconfig-switch-context=false",
                "--no-lb",
            ]),
            &home.join("create.log"),
            240,
        )?;
        let credentials =
            util::output(&mut cluster.k3d(&["kubeconfig", "get", &cluster.name]), 30)?;
        ensure(
            !credentials.is_empty() && credentials.len() <= 1024 * 1024,
            "Invalid disposable kubeconfig",
        )?;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&cluster.kubeconfig)?
            .write_all(&credentials)?;
        let view = util::strict_json(&util::output(
            &mut cluster.kubectl(&["config", "view", "--minify", "-o", "json"]),
            30,
        )?)?;
        private_kubeconfig(&view, &cluster.name, api_port)?;
        let version = util::strict_json(&util::output(
            &mut cluster.kubectl(&["version", "-o", "json"]),
            30,
        )?)?;
        ensure(
            version["serverVersion"]["gitVersion"] == "v1.37.1+k3s1",
            "Unexpected K3s server version",
        )?;
        util::logged(
            &mut cluster.k3d(&[
                "image",
                "import",
                "obsidian-sync:local",
                "--cluster",
                &cluster.name,
                "--mode",
                "direct",
            ]),
            &home.join("import.log"),
            180,
        )?;
        // Static local PV: no unpinned provisioner/helper pods or production manifests changed.
        let pv = home.join("pv.json");
        util::write_json(
            &pv,
            &serde_json::json!({"apiVersion":"v1","kind":"PersistentVolume", "metadata":{"name":"sync-smoke"},
        "spec":{"capacity":{"storage":"50Gi"},"accessModes":["ReadWriteOnce"],"persistentVolumeReclaimPolicy":"Retain",
            "storageClassName":"","claimRef":{"name":"sync-data","namespace":"obsidian-sync"},
            "local":{"path":"/var/lib/sync-smoke"},"nodeAffinity":{"required":{"nodeSelectorTerms":[{"matchExpressions":[{
                "key":"kubernetes.io/hostname","operator":"In","values":[format!("k3d-{}-server-0",cluster.name)]}]}]}}}}),
        )?;
        util::quiet(
            &mut cluster.kubectl(&["apply", "-f", pv.to_str().ok_or("Invalid PV")?]),
            60,
        )?;
        util::quiet(
            &mut cluster.kubectl(&["apply", "-k", "deploy/kustomize/overlays/filesystem"]),
            60,
        )?;
        for provider in ["filesystem", "s3", "gcs", "azure"] {
            util::quiet(
                &mut cluster.kubectl(&[
                    "apply",
                    "--dry-run=server",
                    "-k",
                    &format!("deploy/kustomize/overlays/{provider}"),
                ]),
                60,
            )?;
        }
        cluster.stop_workload()?;
        let vault = cluster.admin(&home, "fixture-create", &["create-vault"])?;
        let credentials = clients::issued_credentials(&cluster.admin(
            &home,
            "fixture-issue",
            &["issue", "--vault", &vault],
        )?)?;
        util::quiet(
            &mut cluster.kubectl(&[
                "-n",
                "obsidian-sync",
                "scale",
                "deployment/obsidian-sync",
                "--replicas=1",
            ]),
            30,
        )?;
        cluster.wait_ready()?;
        let pods = util::strict_json(&util::output(
            &mut cluster.kubectl(&["get", "pods", "--all-namespaces", "-o", "json"]),
            30,
        )?)?;
        let pods = pods["items"]
            .as_array()
            .ok_or("Missing disposable pod inventory")?;
        ensure(
            pods.len() == 1 && pods[0]["metadata"]["namespace"] == "obsidian-sync",
            "Unexpected add-on workload",
        )?;
        for role in ["containers", "initContainers", "ephemeralContainers"] {
            if let Some(containers) = pods[0]["spec"][role].as_array() {
                ensure(
                    containers
                        .iter()
                        .all(|v| v["image"] == "obsidian-sync:local"),
                    "Unexpected fixture workload image",
                )?;
            }
        }
        let port = clients::port()?;
        let log = fs::File::create(work.path().join("port-forward.log"))?;
        let mut c = cluster.kubectl(&[
            "-n",
            "obsidian-sync",
            "port-forward",
            "deployment/obsidian-sync",
            &format!("{port}:8080"),
        ]);
        c.stdout(log.try_clone()?).stderr(log);
        let _forward = Forward(c.spawn()?);
        for endpoint in ["live", "ready"] {
            clients::wait_http(
                &format!("http://127.0.0.1:{port}/health/{endpoint}"),
                Some(204),
                60,
            )?;
        }
        let identity = server_identity(port, &credentials)?;
        let second = util::capture(
            &mut cluster.kubectl(&[
                "-n",
                "obsidian-sync",
                "exec",
                "deployment/obsidian-sync",
                "--",
                "/server",
                "create-vault",
            ]),
            30,
        )?;
        ensure(writer_denied(&second), "Kubernetes writer fencing failed")?;
        util::run(
            &mut cluster.kubectl(&[
                "-n",
                "obsidian-sync",
                "delete",
                "pod",
                "-l",
                "app=obsidian-sync",
                "--wait=true",
            ]),
            90,
        )?;
        cluster.wait_ready()?;
        util::run(
            &mut cluster.kubectl(&[
                "-n",
                "obsidian-sync",
                "exec",
                "deployment/obsidian-sync",
                "--",
                "/server",
                "--version",
            ]),
            30,
        )?;
        drop(_forward);
        let log = fs::File::create(home.join("restart-forward.log"))?;
        let mut c = cluster.kubectl(&[
            "-n",
            "obsidian-sync",
            "port-forward",
            "deployment/obsidian-sync",
            &format!("{port}:8080"),
        ]);
        c.stdout(log.try_clone()?).stderr(log);
        let _restarted = Forward(c.spawn()?);
        clients::wait_http(
            &format!("http://127.0.0.1:{port}/health/ready"),
            Some(204),
            60,
        )?;
        ensure(
            server_identity(port, &credentials)? == identity,
            "PVC restart lost persistent server identity",
        )?;
        Ok(())
    })();
    let cleanup = cluster.remove();
    if result.is_err() || cleanup.is_err() {
        let _retained = work.keep();
    }
    result?;
    cleanup?;
    println!(
        "Disposable k3d Kubernetes smoke passed: readiness, writer fencing and persistent identity; CNI enforcement not certified"
    );
    Ok(())
}
fn server_identity(
    port: u16,
    credentials: &std::collections::BTreeMap<String, String>,
) -> Result<String> {
    let response = clients::http()?
        .get(format!("http://127.0.0.1:{port}/"))
        .basic_auth(&credentials["principal"], Some(&credentials["token"]))
        .send()?
        .error_for_status()?;
    let mut bytes = Vec::new();
    response.take(16385).read_to_end(&mut bytes)?;
    ensure(bytes.len() <= 16384, "Oversized server identity response")?;
    let value = util::strict_json(&bytes)?;
    Ok(value["uuid"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("Missing server identity")?
        .into())
}
pub fn check(root: &Path, features: bool) -> Result {
    let sets: &[&str] = if features {
        &[
            "",
            "s3",
            "gcs",
            "azure",
            "s3,gcs",
            "s3,azure",
            "gcs,azure",
            "s3,gcs,azure",
        ]
    } else {
        &["default"]
    };
    for set in sets {
        println!(
            "FEATURES={}",
            if set.is_empty() {
                "filesystem-only"
            } else {
                set
            }
        );
        for args in [
            vec!["build", "--locked"],
            vec!["build", "--release", "--locked"],
            vec!["clippy", "--workspace", "--all-targets", "--locked"],
            vec!["test", "--workspace", "--locked"],
        ] {
            let clippy = args[0] == "clippy";
            let mut c = util::cmd("cargo", &args, root);
            if features {
                c.args(["--no-default-features", "--features", set]);
            }
            if clippy {
                c.args(["--", "-D", "warnings"]);
            }
            util::run(&mut c, 1800)?;
        }
    }
    util::run(
        &mut util::cmd("cargo", &["fmt", "--all", "--", "--check"], root),
        60,
    )?;
    if !features {
        util::run(&mut util::cmd("cargo", &["audit"], root), 300)?;
        util::run(&mut util::cmd("cargo", &["deny", "check"], root), 300)?;
        docs::sync(root, true)?;
        docs::check(root)?;
    }
    Ok(())
}
pub fn benchmark(root: &Path) -> Result {
    util::run(
        &mut util::cmd(
            "cargo",
            &["build", "--release", "--locked", "--example", "benchmark"],
            root,
        ),
        1200,
    )?;
    util::run(
        &mut util::cmd(
            "/usr/bin/time",
            &[
                if cfg!(target_os = "macos") {
                    "-l"
                } else {
                    "-v"
                },
                "target/release/examples/benchmark",
            ],
            root,
        ),
        600,
    )
}
