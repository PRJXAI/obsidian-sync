use crate::{Result, clients, docs, ensure, util};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

pub const KIND: &str =
    "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5";
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
    for path in [
        "Cargo.toml",
        "config/filesystem.toml",
        "xtask/Cargo.toml",
        "xtask/src/lib.rs",
        ".cargo/config.toml",
    ] {
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
        crate::security::HELPER
    );
    for path in [
        "Cargo.toml",
        "config/filesystem.toml",
        "xtask/Cargo.toml",
        "xtask/src/lib.rs",
        ".cargo/config.toml",
    ] {
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
    println!("Compose and Kustomize render; API validation is only against disposable kind");
    Ok(())
}
struct Compose {
    root: PathBuf,
    project: String,
    file: &'static str,
    env: Vec<(String, String)>,
}
impl Compose {
    fn command(&self, args: &[&str]) -> Command {
        let mut c = util::cmd(
            "docker",
            &["compose", "-p", &self.project, "-f", self.file],
            &self.root,
        );
        c.args(args).envs(self.env.iter().map(|(k, v)| (k, v)));
        c
    }
}
impl Drop for Compose {
    fn drop(&mut self) {
        let _ = util::cleanup(&mut self.command(&["down", "-v"]), 90);
    }
}
pub fn s3(root: &Path) -> Result {
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
        file: "docker-compose.test-s3.yml",
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
                    crate::security::HELPER,
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
        file: "docker-compose.yml",
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
}
pub fn fenced_command(root: &Path, kubeconfig: &Path, program: &str, args: &[&str]) -> Command {
    let mut c = util::cmd(program, &[], root);
    if program == "kubectl" {
        c.arg("--kubeconfig").arg(kubeconfig);
    }
    c.env("KUBECONFIG", kubeconfig).args(args);
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
    pub fn kind(&self, args: &[&str]) -> Command {
        fenced_command(&self.root, &self.kubeconfig, "kind", args)
    }
    pub fn kubectl(&self, args: &[&str]) -> Command {
        fenced_command(&self.root, &self.kubeconfig, "kubectl", args)
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
        let _ = util::cleanup(
            &mut self.kind(&[
                "delete",
                "cluster",
                "--name",
                &self.name,
                "--kubeconfig",
                self.kubeconfig.to_str().unwrap_or(""),
            ]),
            120,
        );
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
    util::local_docker(root)?;
    let work = tempfile::tempdir()?;
    let cluster = Cluster {
        root: root.into(),
        name: format!("obsidian-sync-smoke-{}", &util::random_hex()[..12]),
        kubeconfig: work.path().join("kubeconfig"),
    };
    util::run(
        &mut cluster.kind(&[
            "create",
            "cluster",
            "--name",
            &cluster.name,
            "--kubeconfig",
            cluster.kubeconfig.to_str().ok_or("Invalid kubeconfig")?,
            "--wait",
            "120s",
            "--image",
            KIND,
        ]),
        240,
    )?;
    util::run(
        &mut cluster.kind(&[
            "load",
            "docker-image",
            "obsidian-sync:local",
            "--name",
            &cluster.name,
        ]),
        180,
    )?;
    util::run(
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
    cluster.wait_ready()?;
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
    println!("Disposable Kubernetes smoke passed; default kind CNI does not verify NetworkPolicy");
    Ok(())
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
