use crate::{Result, ensure, util};
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

pub const GITLEAKS: &str = "ghcr.io/gitleaks/gitleaks:latest@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";
// Build/test-only utilities reuse the required compiler base; no separate OS helper.
pub const BUILD_IMAGE: &str = "rust:1.99.1-alpine3.24@sha256:7e9e2d068a107a2adafd19930011178d14a78326053cd4c3a9f7ad3fd049557d";
pub fn image_regex() -> Result<Regex> {
    Ok(Regex::new(
        r"(?:[a-z0-9.-]+/)*[a-z0-9_-]+:[A-Za-z0-9_.-]+@sha256:[a-f0-9]{64}",
    )?)
}
pub fn inventory(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let expression = image_regex()?;
    let exact = Regex::new(&format!("^(?:{})$", expression.as_str()))?;
    let mut paths = vec![root.join("Dockerfile")];
    for folder in ["deploy", ".github", "scripts", "xtask/src"] {
        if !root.join(folder).exists() {
            continue;
        }
        for item in walkdir::WalkDir::new(root.join(folder)).follow_links(false) {
            let item = item?;
            if item.file_type().is_file()
                && item
                    .path()
                    .extension()
                    .is_some_and(|e| ["yaml", "yml", "sh", "rs"].iter().any(|v| e == *v))
            {
                paths.push(item.into_path());
            }
        }
    }
    for item in fs::read_dir(root)? {
        let path = item?.path();
        if path
            .file_name()
            .is_some_and(|s| s.to_string_lossy().starts_with("docker-compose"))
            && path.extension().is_some_and(|e| e == "yml")
        {
            paths.push(path);
        }
    }
    paths.sort();
    paths.dedup();
    let mut images = BTreeMap::<String, BTreeSet<String>>::new();
    let yaml_image = Regex::new(r#"(?m)^\s*image:\s*['\"]?([^'\"\s#]+)"#)?;
    for path in paths {
        let relative = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("Invalid inventory path")?;
        let text = String::from_utf8(util::read(
            &util::regular_source(root, Path::new(relative))?,
            4 * 1024 * 1024,
        )?)?;
        for m in expression.find_iter(&text) {
            images
                .entry(m.as_str().into())
                .or_default()
                .insert(relative.into());
        }
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            for capture in yaml_image.captures_iter(&text) {
                let image = &capture[1];
                let release = relative == "deploy/compose.release.yml"
                    && image == "${SYNC_RELEASE_IMAGE:?Set";
                ensure(
                    image == "obsidian-sync:local" || release || exact.is_match(image),
                    "Unpinned external deployment/test image",
                )?;
            }
        }
    }
    let text = fs::read_to_string(root.join("Dockerfile"))?;
    let mut stages = BTreeSet::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(image) = line.strip_prefix("# syntax=") {
            ensure(exact.is_match(image), "Unpinned frontend")?;
        }
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts
            .first()
            .is_some_and(|word| word.eq_ignore_ascii_case("FROM"))
        {
            ensure(
                [2, 4].contains(&parts.len())
                    && (stages.contains(parts[1]) || exact.is_match(parts[1])),
                "Unsupported or unpinned external base",
            )?;
            ensure(
                parts.len() != 4 || parts[2].eq_ignore_ascii_case("AS"),
                "Unpinned external base",
            )?;
            if parts.len() == 4 && parts[2].eq_ignore_ascii_case("AS") {
                stages.insert(parts[3].to_string());
            }
        }
    }
    ensure(!images.is_empty(), "Empty image inventory")?;
    Ok(images)
}
pub fn sandbox_args(name: &str) -> Vec<String> {
    [
        "run",
        "--rm",
        "--name",
        name,
        "--read-only",
        "--user",
        &util::uid_gid(),
        "--env",
        "HOME=/tmp",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "128",
        "--memory",
        "3g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=1536m,mode=1777",
    ]
    .into_iter()
    .map(String::from)
    .collect()
}
fn sandbox(root: &Path, container: &util::Container) -> Command {
    let mut c = util::cmd("docker", &[], root);
    c.args(sandbox_args(&container.name));
    c
}
fn mount(c: &mut Command, source: &Path, destination: &str, readonly: bool) -> Result {
    ensure(
        !source.to_string_lossy().contains(','),
        "Comma in bind source",
    )?;
    c.args([
        "--mount",
        &format!(
            "type=bind,source={},target={destination}{}",
            source.display(),
            if readonly { ",readonly" } else { "" }
        ),
    ]);
    Ok(())
}
pub fn history_snapshot(root: &Path, destination: &Path) -> Result {
    util::quiet(
        &mut util::cmd(
            "git",
            &[
                "clone",
                "--quiet",
                "--mirror",
                "--no-local",
                ".",
                destination.to_str().ok_or("Invalid history path")?,
            ],
            root,
        ),
        60,
    )?;
    util::quiet(
        &mut util::cmd(
            "git",
            &[
                "--git-dir",
                destination.to_str().ok_or("Invalid history path")?,
                "config",
                "--remove-section",
                "remote.origin",
            ],
            root,
        ),
        30,
    )
}
fn secret_scan(root: &Path, source: &Path, output: &Path, history: bool) -> Result {
    let container = util::Container::new(root, "sync-secret-scan");
    let mut c = sandbox(root, &container);
    c.args(["--network", "none"]);
    mount(
        &mut c,
        source,
        if history { "/repo" } else { "/source" },
        true,
    )?;
    mount(&mut c, output, "/reports", false)?;
    if history {
        c.args([
            "--env",
            "GIT_CONFIG_COUNT=1",
            "--env",
            "GIT_CONFIG_KEY_0=safe.directory",
            "--env",
            "GIT_CONFIG_VALUE_0=/repo",
        ]);
    }
    c.args([
        GITLEAKS,
        if history { "git" } else { "dir" },
        if history { "/repo" } else { "/source" },
    ]);
    if history {
        c.arg("--log-opts=--all");
    }
    c.args([
        "--redact=100",
        "--exit-code",
        "1",
        "--report-format",
        "json",
        "--report-path",
        if history {
            "/reports/gitleaks-history.json"
        } else {
            "/reports/gitleaks.json"
        },
    ]);
    util::logged(
        &mut c,
        &output.join(if history {
            "gitleaks-history.log"
        } else {
            "gitleaks.log"
        }),
        300,
    )
}
pub fn native_identity(root: &Path, builder: &str) -> Result<Vec<u8>> {
    let execute = |program: &str, args: &[&str]| -> Result<Vec<u8>> {
        let container = util::Container::new(root, "sync-native-inventory");
        let mut c = sandbox(root, &container);
        c.args(["--network", "none", "--entrypoint", program, builder])
            .args(args);
        util::output(&mut c, 60)
    };
    let mut result = execute("rustc", &["--version"])?;
    let directory = String::from_utf8(execute("rustc", &["--print", "target-libdir"])?)?;
    let libc = format!("{}/self-contained/libc.a", directory.trim());
    ensure(
        libc.starts_with('/') && !libc.contains('\n'),
        "Invalid native archive location",
    )?;
    result.extend(execute("sha256sum", &[&libc])?);
    let object = execute("ar", &["p", &libc, "version.lo"])?;
    for bytes in object.split(|b| !(b.is_ascii_graphic() || *b == b' ')) {
        if bytes.len() >= 4 {
            result.extend_from_slice(bytes);
            result.push(b'\n');
        }
    }
    Ok(result)
}
pub fn scan_security(root: &Path) -> Result {
    scan_sources(root)?;
    crate::sbom::generate(root, "obsidian-sync:local", "obsidian-sync:builder", None)?;
    crate::grype::scan_generated(root, &root.join(".work/sbom"))
}
pub fn scan_sources(root: &Path) -> Result {
    util::local_docker(root)?;
    let output = root.join(".work/security");
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    for name in ["rustsec.json", "gitleaks.json", "gitleaks-history.json"] {
        let p = output.join(name);
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    let mut audit = util::cmd("cargo", &["audit", "--json"], root);
    audit.stdout(fs::File::create(output.join("rustsec.json"))?);
    util::run(&mut audit, 300)?;
    util::run(&mut util::cmd("cargo", &["deny", "check"], root), 300)?;
    let work = tempfile::Builder::new()
        .prefix("scan-")
        .tempdir_in(root.join(".work"))?;
    let source = work.path().join("source");
    fs::create_dir(&source)?;
    util::copy_public_sources(root, &source)?;
    secret_scan(root, &source, &output, false)?;
    ensure(
        source.join("Cargo.lock").metadata()?.len() > 0,
        "Vacuous source input",
    )?;
    // Verify the daemon sees the same source, not merely the host filesystem.
    let check = util::Container::new(root, "sync-source-mount-check");
    let mut c = sandbox(root, &check);
    c.args(["--network", "none"]);
    mount(&mut c, &source, "/source", true)?;
    c.args([
        "--entrypoint",
        "test",
        BUILD_IMAGE,
        "-s",
        "/source/Cargo.lock",
    ]);
    util::run(&mut c, 60)?;
    if util::quiet(
        &mut util::cmd("git", &["rev-parse", "--verify", "HEAD"], root),
        30,
    )
    .is_ok()
    {
        let mirror = work.path().join("history.git");
        history_snapshot(root, &mirror)?;
        secret_scan(root, &mirror, &output, true)?;
    }
    Ok(())
}
pub fn recorded_command(c: &Command) -> Vec<String> {
    c.get_args()
        .map(|v| v.to_string_lossy().into_owned())
        .collect()
}
