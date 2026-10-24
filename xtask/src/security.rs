use crate::{Result, ensure, evidence, images, util};
use chrono::Utc;
use regex::Regex;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
};

pub const TRIVY: &str =
    "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c";
pub const GITLEAKS: &str = "ghcr.io/gitleaks/gitleaks:latest@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";
pub const HELPER: &str =
    "alpine:3.23.7@sha256:ff7f0c727dd796aa36787bfcd9a64bf35a6ce72a73451b3359fde849b6703d63";
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
fn scan_remote(
    root: &Path,
    output: &Path,
    cache: &Path,
    args: &[&str],
    log: &Path,
    timeout: u64,
) -> Result<i32> {
    let container = util::Container::new(root, "sync-chain-scan");
    let mut c = sandbox(root, &container);
    mount(&mut c, output, "/reports", false)?;
    mount(&mut c, cache, "/cache", false)?;
    c.args([TRIVY, "--cache-dir", "/cache"]).args(args);
    let file = fs::File::create(log)?;
    c.stdout(file.try_clone()?).stderr(file);
    match util::wait(&mut c, timeout) {
        Ok(status) => Ok(status.code().unwrap_or(125)),
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::TimedOut) =>
        {
            Ok(124)
        }
        Err(e) => Err(e),
    }
}
pub fn scan_supply_chain(root: &Path, platform: &str) -> Result {
    ensure(
        ["linux/amd64", "linux/arm64"].contains(&platform),
        "Unsupported platform",
    )?;
    util::local_docker(root)?;
    let output = root
        .join(".work/security/supply-chain")
        .join(platform.split('/').next_back().ok_or("Invalid platform")?);
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let summary_file = output.join("summary.json");
    if summary_file.exists() {
        fs::remove_file(&summary_file)?;
    }
    let cache = root.join(".work/trivy-cache");
    fs::create_dir_all(&cache)?;
    ensure(
        scan_remote(
            root,
            &output,
            &cache,
            &["image", "--download-db-only", "--quiet"],
            &output.join("database.log"),
            600,
        )? == 0,
        "Database update failed",
    )?;
    let mut summary = Vec::new();
    for (index, (image, sources)) in inventory(root)?.into_iter().enumerate() {
        let report = format!("image-{index:02}.json");
        let path = output.join(&report);
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let status = scan_remote(
            root,
            &output,
            &cache,
            &[
                "image",
                "--timeout",
                "3m",
                "--skip-db-update",
                "--image-src",
                "remote",
                "--platform",
                platform,
                "--scanners",
                "vuln",
                "--list-all-pkgs",
                "--exit-code",
                "1",
                "--format",
                "json",
                "--output",
                &format!("/reports/{report}"),
                &image,
            ],
            &output.join(format!("image-{index:02}.log")),
            240,
        )?;
        let mut entry = json!({"image":image,"sources":sources,"exit_code":status,"report":report});
        match util::json(&path).and_then(|r| evidence::findings(&r, Some(&image), Utc::now())) {
            Ok(findings) => {
                entry["counts"] = json!(
                    evidence::SEVERITIES
                        .into_iter()
                        .map(|s| (s, findings.iter().filter(|v| v["Severity"] == s).count()))
                        .collect::<BTreeMap<_, _>>()
                );
                entry["unique_advisories"] = json!(
                    findings
                        .iter()
                        .filter_map(|v| v["VulnerabilityID"].as_str())
                        .collect::<BTreeSet<_>>()
                        .len()
                );
                if !findings.is_empty() && status == 0 {
                    entry["exit_code"] = json!(1);
                }
            }
            Err(_) => entry["exit_code"] = json!(if status == 0 { 1 } else { status }),
        }
        println!(
            "{} {image}",
            if entry["exit_code"] == 0 {
                "PASS"
            } else {
                "FAIL"
            }
        );
        summary.push(entry);
    }
    util::write_json(
        &summary_file,
        &json!({"scanner":TRIVY,"platform":platform,"created_at":Utc::now().to_rfc3339(),"images":summary}),
    )?;
    ensure(
        summary.iter().all(|v| v["exit_code"] == 0),
        "Supply-chain findings/errors remain blocking",
    )
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
fn archive_scan(root: &Path, archive: &Path, output: &Path, cache: &Path, builder: bool) -> Result {
    let container = util::Container::new(root, "sync-image-scan");
    let mut c = sandbox(root, &container);
    mount(&mut c, archive, "/image.tar", true)?;
    mount(&mut c, output, "/reports", false)?;
    mount(&mut c, cache, "/cache", false)?;
    c.args([
        TRIVY,
        "--cache-dir",
        "/cache",
        "image",
        "--input",
        "/image.tar",
        "--scanners",
        "vuln",
        "--list-all-pkgs",
        "--exit-code",
        "1",
        "--format",
        "json",
        "--output",
        if builder {
            "/reports/trivy-builder.json"
        } else {
            "/reports/trivy.json"
        },
    ]);
    util::logged(
        &mut c,
        &output.join(if builder {
            "trivy-builder.log"
        } else {
            "trivy-runtime.log"
        }),
        600,
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
    util::local_docker(root)?;
    let output = root.join(".work/security");
    let cache = root.join(".work/trivy-cache");
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    fs::create_dir_all(&cache)?;
    for name in [
        "rustsec.json",
        "gitleaks.json",
        "gitleaks-history.json",
        "trivy.json",
        "trivy-builder.json",
        "trivy-version.txt",
        "image-inspect.json",
        "image-id.txt",
        "native-toolchain.txt",
        "cargo-metadata.json",
    ] {
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
    c.args([HELPER, "test", "-s", "/source/Cargo.lock"]);
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
    let inspected = images::inspect(root, "obsidian-sync:local")?;
    util::write_json(&output.join("image-inspect.json"), &json!([inspected]))?;
    fs::write(
        output.join("image-id.txt"),
        format!("{}\n", inspected["Id"].as_str().ok_or("Missing ID")?),
    )?;
    let runtime = work.path().join("runtime.tar");
    images::export(root, "obsidian-sync:local", &runtime)?;
    archive_scan(root, &runtime, &output, &cache, false)?;
    let report = util::json(&output.join("trivy.json"))?;
    images::verify_content(
        &report,
        &inspected,
        &images::saved_config(&runtime)?,
        Utc::now(),
    )?;
    let builder = if let Ok(image) = std::env::var("SYNC_SECURITY_BUILDER_IMAGE") {
        image
    } else {
        util::run(
            &mut util::cmd(
                "docker",
                &[
                    "build",
                    "--target",
                    "build",
                    "-t",
                    "obsidian-sync:audit-builder",
                    ".",
                ],
                root,
            ),
            1200,
        )?;
        "obsidian-sync:audit-builder".into()
    };
    let builder_archive = work.path().join("builder.tar");
    let builder_material = images::export(root, &builder, &builder_archive)?;
    archive_scan(root, &builder_archive, &output, &cache, true)?;
    fs::write(
        output.join("native-toolchain.txt"),
        native_identity(
            root,
            builder_material["image_id"]
                .as_str()
                .ok_or("Missing builder ID")?,
        )?,
    )?;
    let container = util::Container::new(root, "sync-scanner-version");
    let mut c = sandbox(root, &container);
    c.args(["--network", "none", TRIVY, "--version"]);
    fs::write(output.join("trivy-version.txt"), util::output(&mut c, 30)?)?;
    fs::write(
        output.join("cargo-metadata.json"),
        util::output(
            &mut util::cmd(
                "cargo",
                &["metadata", "--locked", "--format-version", "1"],
                root,
            ),
            180,
        )?,
    )?;
    println!(
        "Runtime/builder scans passed; the full supply-chain and native patch review remain required"
    );
    Ok(())
}

pub fn ledger(root: &Path, platform: &str, revision: &str) -> Result {
    ensure(
        crate::policy::is_revision(revision),
        "Invalid source revision",
    )?;
    ensure(
        ["linux/amd64", "linux/arm64"].contains(&platform),
        "Invalid platform",
    )?;
    let output = root
        .join(".work/security/supply-chain")
        .join(platform.split('/').next_back().ok_or("Missing platform")?);
    let ledger_file = output.join("findings-ledger.json");
    if ledger_file.symlink_metadata().is_ok() {
        fs::remove_file(&ledger_file)?;
    }
    let summary = util::json(&output.join("summary.json"))?;
    ensure(
        summary["scanner"] == TRIVY && summary["platform"] == platform,
        "Unexpected scan provenance",
    )?;
    let entries = summary["images"]
        .as_array()
        .ok_or("Missing image inventory")?;
    let inventory = inventory(root)?;
    ensure(entries.len() == inventory.len(), "Incomplete inventory")?;
    let mut records = Vec::new();
    let mut valid = true;
    for (index, ((image, _), entry)) in inventory.iter().zip(entries).enumerate() {
        let filename = format!("image-{index:02}.json");
        ensure(
            entry["image"] == *image && entry["report"] == filename,
            "Reordered/substituted inventory",
        )?;
        let path = output.join(filename);
        let report = util::json(&path)?;
        let findings = evidence::findings(&report, Some(image), Utc::now())?;
        valid &= entry["exit_code"] == if findings.is_empty() { 0 } else { 1 };
        let findings = findings.iter().map(|v| { let key = json!([platform,image,report["Metadata"]["ImageID"],v["_scan_target"],v["PkgPath"],v["PkgName"],v["InstalledVersion"],v["VulnerabilityID"]]); json!({"id":util::digest(key.to_string().as_bytes()),"target":v["_scan_target"],"package_path":v["PkgPath"],"advisory":v["VulnerabilityID"],"package":v["PkgName"],"installed_version":v["InstalledVersion"],"fixed_version":v["FixedVersion"],"severity":v["Severity"],"status":"under_investigation","applicability_evidence":null,"owner":null}) }).collect::<Vec<_>>();
        records.push(json!({"image":image,"config_digest":report["Metadata"]["ImageID"],"layers":report["Metadata"]["DiffIDs"],"report_sha256":util::hash(&path)?,"findings":findings}));
    }
    util::write_json(
        &output.join("findings-ledger.json"),
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"source_revision":revision,"platform":platform,"scanner":TRIVY,"complete":valid,"images":records,"native_review":{"rust_bundled_musl":"pending","vendored_crypto":"pending","build_scripts_proc_macros":"pending","tool_image_native_code":"pending"},"authorization":"none; triage inventory does not waive findings"}),
    )?;
    ensure(valid, "Incomplete/error scan evidence")
}

pub fn public_summary(root: &Path, revision: &str) -> Result {
    ensure(crate::policy::is_revision(revision), "Invalid revision")?;
    let output = root.join(".work/public-security");
    ensure(!output.exists(), "Refusing stale public output directory")?;
    fs::create_dir(&output)?;
    let raw = root.join(".work/security");
    let mut results = BTreeMap::<String, Value>::new();
    // Deliberately no arbitrary messages, file paths, matches, authors, labels,
    // environment values or raw provider/scanner logs in public artifacts.
    for (label, name) in [("runtime", "trivy.json"), ("builder", "trivy-builder.json")] {
        let value = match util::json(&raw.join(name))
            .and_then(|r| evidence::findings(&r, None, Utc::now()))
        {
            Ok(values) => {
                json!({"status":if values.is_empty() {"pass"} else {"fail"},"findings":values.len()})
            }
            Err(_) => json!({"status":"error"}),
        };
        results.insert(label.into(), value);
    }
    for name in ["gitleaks.json", "gitleaks-history.json"] {
        let value = match util::json(&raw.join(name)).and_then(|v| {
            v.as_array()
                .map(Vec::len)
                .ok_or_else(|| "Invalid secret report".into())
        }) {
            Ok(n) => json!({"status":if n==0 {"pass"} else {"fail"},"findings":n}),
            Err(_) => json!({"status":"error"}),
        };
        results.insert(name.into(), value);
    }
    let supply = raw.join("supply-chain/amd64/summary.json");
    let value = match util::json(&supply) {
        Ok(v) => {
            let count = inventory(root)?.len();
            let images = v["images"].as_array();
            let complete = images.is_some_and(|i| i.len() == count);
            let failed = images
                .map(|i| i.iter().filter(|v| v["exit_code"] != 0).count())
                .unwrap_or(count);
            json!({"status":if !complete {"error"} else if failed==0 {"pass"} else {"fail"},"images":count,"failed_images":failed})
        }
        Err(_) => json!({"status":"error"}),
    };
    results.insert("supply_chain".into(), value);
    util::write_json(
        &output.join("summary.json"),
        &json!({"schema_version":1,"source_revision":revision,"results":results,"raw_reports_published":false,"raw_evidence_archive":"owner_approved_private_destination_pending"}),
    )
}

pub fn recorded_command(c: &Command) -> Vec<String> {
    c.get_args()
        .map(|v| v.to_string_lossy().into_owned())
        .collect()
}
