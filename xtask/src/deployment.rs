use crate::{Result, clients, docs, ensure, fixture::DataCleanup, util};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(test)]
#[path = "../tests/fixtures/rustfs/native.rs"]
mod rustfs_candidate;

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
        "src/couch/http/codec.rs",
        "src/blob.rs",
        "src/replay.rs",
        "xtask/src/fixture.rs",
        "config/filesystem.toml",
        "xtask/Cargo.toml",
        "xtask/src/lib.rs",
        "xtask/src/accepted-risks.json",
        "xtask/tests/support/mod.rs",
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
        "src/couch/http/private-canary.toml",
        "src/couch/http/.env",
        "src/couch/http/private/nested.rs",
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
        "xtask/tests/fixtures/retired-private.rs",
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
    println!(
        "Optional Compose and Kustomize examples render; no cluster/API validation is performed"
    );
    Ok(())
}

struct Compose {
    root: PathBuf,
    project: String,
    file: PathBuf,
    env: Vec<(String, String)>,
    finished: bool,
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
    fn finish(&mut self) -> Result {
        if !self.finished {
            util::cleanup(&mut self.command(&["down", "-v"]), 90)?;
            self.finished = true;
        }
        Ok(())
    }
}
impl Drop for Compose {
    fn drop(&mut self) {
        let _ = self.finish();
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
    let mut compose = Compose {
        root: root.into(),
        finished: false,
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
    // An unauthenticated S3 root is ready when it rejects access, not while
    // RustFS still answers 503 during initialization. Keep writes in the contract.
    clients::wait_http(&format!("http://127.0.0.1:{port}/"), Some(403), 120)?;
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
    )?;
    compose.finish()?;
    work.close()?;
    Ok(())
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
    let mut cleanup = DataCleanup::new(root, &data);
    let port = clients::port()?;
    let mut compose = Compose {
        root: root.into(),
        finished: false,
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
    compose.finish()?;
    cleanup.finish()?;
    work.close()?;
    println!(
        "Compose smoke passed: private probes, writer exclusion, graceful stop and persistent restart"
    );
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
