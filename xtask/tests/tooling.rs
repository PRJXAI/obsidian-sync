#![forbid(unsafe_code)]
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::{fs, io::Cursor, os::unix::fs::symlink, path::Path};
use xtask::{
    Result, clients, deployment, docs, evidence, grype, images, policy, sbom, security,
    supply_sbom, util,
};
mod support;

fn fixture() -> Result<tempfile::TempDir> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    fs::create_dir(root.join("docs"))?;
    for file in ["README.md", "AGENTS.md", "llms.txt"] {
        fs::write(root.join(file), "# Public test fixture\n")?;
    }
    util::quiet(&mut util::cmd("git", &["init", "-q"], root), 30)?;
    Ok(temp)
}
fn put(root: &Path, path: &str, text: &str) -> Result {
    let target = root.join(path);
    fs::create_dir_all(target.parent().ok_or("Missing parent")?)?;
    fs::write(target, text)?;
    Ok(())
}
fn commit(root: &Path) -> Result {
    util::quiet(&mut util::cmd("git", &["add", "."], root), 30)?;
    util::quiet(
        &mut util::cmd(
            "git",
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "public fixture",
            ],
            root,
        ),
        30,
    )
}
fn pin() -> String {
    format!("alpine:fixture@sha256:{}", "a".repeat(64))
}
fn saved(path: &Path, config_name: &str, config: &[u8]) -> Result {
    let mut archive = tar::Builder::new(fs::File::create(path)?);
    for (name, data) in [
        (
            "manifest.json",
            serde_json::to_vec(&json!([{"Config":config_name}]))?,
        ),
        (config_name, config.to_vec()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, name, Cursor::new(data))?;
    }
    archive.finish()?;
    Ok(())
}

#[test]
fn docs_create_update_drift_and_review() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    docs::create(root, Path::new("docs/nested/new.md"), "New")?;
    assert!(docs::check(root).is_err());
    put(root, "content.txt", "# Verified\n")?;
    docs::update(
        root,
        Path::new("docs/nested/new.md"),
        &root.join("content.txt"),
    )?;
    docs::review(root, "reviewed fixture")?;
    docs::check(root)?;
    put(root, "src/lib.rs", "// changed\n")?;
    assert!(docs::check(root).is_err());
    docs::review(root, "reviewed changed source")?;
    docs::check(root)
}
#[test]
fn docs_llm_links_and_ignored_configuration_privacy() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    put(root, ".gitignore", "config/private.toml\n")?;
    put(root, "config/private.toml", "private fixture")?;
    docs::review(root, "public fixtures")?;
    assert!(!fs::read_to_string(root.join("docs/review.json"))?.contains("config/private.toml"));
    put(root, "llms.txt", "[missing](docs/missing.md)\n")?;
    assert!(docs::check(root).is_err());
    put(root, "llms.txt", "[README](README.md)\n")?;
    docs::check(root)
}
#[test]
fn generated_map_excludes_ignored_toml_and_includes_rust_tooling() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    put(root, ".gitignore", "config/private.toml\n")?;
    for provider in ["filesystem", "s3", "gcs", "azure"] {
        put(
            root,
            &format!("config/{provider}.toml"),
            "# Public fixture\n",
        )?;
    }
    put(root, "config/private.toml", "private fixture")?;
    put(root, "xtask/src/lib.rs", "// Rust tooling\n")?;
    docs::sync(root, false)?;
    let map = fs::read_to_string(root.join("docs/source-map.md"))?;
    assert!(!map.contains("config/private.toml"));
    assert!(map.contains("config/filesystem.toml") && map.contains("xtask/src/lib.rs"));
    docs::sync(root, true)?;
    put(root, "deploy/kustomize/base/config.toml", "stale")?;
    assert!(docs::sync(root, true).is_err());
    Ok(())
}
#[test]
fn ignore_rules_preserve_required_manifests() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    fs::copy(xtask::root().join(".gitignore"), root.join(".gitignore"))?;
    for (paths, ignored) in [
        (
            &[
                ".env",
                ".env.production",
                ".pi-loop.json",
                ".pi-loop.json.lock",
                "nested/.env",
                "nested/.env.local",
                "config/local.toml",
                "local.toml",
                "nested/secret.toml",
            ][..],
            true,
        ),
        (
            &[
                ".env.example",
                "Cargo.toml",
                "Cargo.lock",
                "xtask/Cargo.toml",
                ".cargo/config.toml",
                "rust-toolchain.toml",
                "deny.toml",
                "config/filesystem.toml",
                "config/s3.toml",
                "config/gcs.toml",
                "config/azure.toml",
                "deploy/kustomize/base/config.toml",
                "llms.txt",
            ][..],
            false,
        ),
    ] {
        for path in paths {
            let status = util::wait(
                &mut util::cmd(
                    "git",
                    &[
                        "-c",
                        "core.excludesFile=/dev/null",
                        "check-ignore",
                        "--no-index",
                        "-q",
                        "--",
                        path,
                    ],
                    root,
                ),
                30,
            )?;
            assert_eq!(status.success(), ignored, "{path}");
        }
    }
    put(root, ".pi-loop.json", "SYNTHETIC_PRIVATE_LOOP_CANARY")?;
    put(root, ".pi-loop.json.lock", "SYNTHETIC_PRIVATE_LOOP_LOCK")?;
    let public = tempfile::tempdir()?;
    util::copy_public_sources(root, public.path())?;
    assert!(!public.path().join(".pi-loop.json").exists());
    assert!(!public.path().join(".pi-loop.json.lock").exists());
    Ok(())
}
#[test]
fn docs_reject_traversal_parent_symlinks_hardlinks_and_untracked_delete() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    assert!(docs::create(root, Path::new("../escape.md"), "X").is_err());
    docs::create(root, Path::new("docs/new.md"), "New")?;
    assert!(docs::delete(root, Path::new("docs/new.md"), "stale", true).is_err());
    symlink(root.join("README.md"), root.join("docs/link.md"))?;
    assert!(docs::update(root, Path::new("docs/link.md"), &root.join("AGENTS.md")).is_err());
    symlink(root, root.join("docs/parent"))?;
    assert!(docs::create(root, Path::new("docs/parent/escaped.md"), "X").is_err());
    assert!(!root.join("escaped.md").exists());
    fs::hard_link(root.join("README.md"), root.join("docs/hard.md"))?;
    assert!(docs::update(root, Path::new("docs/hard.md"), &root.join("AGENTS.md")).is_err());
    Ok(())
}
#[test]
fn docs_delete_requires_history_confirmation_clean_content_and_no_links() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    put(root, "docs/old.md", "# Old\n")?;
    put(root, "README.md", "[old](docs/old.md)\n")?;
    commit(root)?;
    assert!(docs::delete(root, Path::new("docs/old.md"), "stale", false).is_err());
    assert!(docs::delete(root, Path::new("docs/old.md"), "stale", true).is_err());
    put(root, "README.md", "# Test\n")?;
    put(root, "docs/old.md", "# Valuable uncommitted update\n")?;
    assert!(docs::delete(root, Path::new("docs/old.md"), "superseded", true).is_err());
    put(root, "docs/old.md", "# Old\n")?;
    docs::delete(root, Path::new("docs/old.md"), "superseded", true)?;
    assert!(!root.join("docs/old.md").exists());
    Ok(())
}
fn content_fixture() -> (Value, Value, Vec<u8>) {
    let layers = json!([format!("sha256:{}", "a".repeat(64))]);
    let config=serde_json::to_vec(&json!({"rootfs":{"diff_ids":layers},"config":{"User":"65532:65532","Entrypoint":["/server"]}})).unwrap();
    let report = json!({"CreatedAt":Utc::now().to_rfc3339(),"Metadata":{"ImageID":format!("sha256:{}",util::digest(&config)),"DiffIDs":layers},"Results":[{"Vulnerabilities":[]}]});
    let inspected = json!({"Id":format!("sha256:{}","b".repeat(64)),"RootFS":{"Layers":layers},"Os":"linux","Architecture":"arm64"});
    (report, inspected, config)
}
#[test]
fn release_binds_config_not_oci_index() -> Result {
    let (report, inspected, config) = content_fixture();
    assert_eq!(
        images::verify_content(&report, &inspected, &config, Utc::now())?,
        inspected["Id"].as_str().unwrap()
    );
    Ok(())
}
#[test]
fn release_rejects_substitution_unknown_and_stale_evidence() {
    for kind in [
        "config",
        "layers",
        "finding",
        "unknown",
        "empty",
        "stale",
        "future",
        "identity",
        "root",
        "entrypoint",
        "naive",
    ] {
        let (mut report, mut inspected, mut config) = content_fixture();
        match kind {
            "config" => config.push(b' '),
            "layers" => inspected["RootFS"]["Layers"] = json!([]),
            "finding" | "unknown" => {
                report["Results"][0]["Vulnerabilities"] =
                    json!([{"Severity":if kind=="unknown"{"UNKNOWN"}else{"LOW"}}])
            }
            "empty" => report["Results"] = json!([]),
            "stale" | "future" => {
                report["CreatedAt"] = json!(
                    (Utc::now() + Duration::days(if kind == "future" { 2 } else { -2 }))
                        .to_rfc3339()
                )
            }
            "identity" => inspected["Id"] = json!("mutable:tag"),
            "naive" => report["CreatedAt"] = json!("2026-10-23T00:00:00"),
            "root" | "entrypoint" => {
                let mut value: Value = serde_json::from_slice(&config).unwrap();
                value["config"][if kind == "root" { "User" } else { "Entrypoint" }] =
                    json!("changed");
                config = serde_json::to_vec(&value).unwrap();
                report["Metadata"]["ImageID"] = json!(format!("sha256:{}", util::digest(&config)));
            }
            _ => unreachable!(),
        }
        assert!(
            images::verify_content(&report, &inspected, &config, Utc::now()).is_err(),
            "{kind}"
        );
    }
}
#[test]
fn sbom_stages_only_explicit_public_inputs_and_rejects_symlinks() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    let destination = tempfile::tempdir()?;
    for name in sbom::SOURCE_FILES {
        put(root, name, "public manifest")?;
    }
    put(root, ".env", "SYNTHETIC_CANARY=not-real\n")?;
    let materials = sbom::stage_source(root, destination.path())?;
    assert_eq!(materials.len(), sbom::SOURCE_FILES.len());
    assert!(!destination.path().join(".env").exists());
    fs::remove_file(root.join("Cargo.lock"))?;
    symlink(root.join(".env"), root.join("Cargo.lock"))?;
    assert!(sbom::stage_source(root, destination.path()).is_err());
    Ok(())
}
#[test]
fn saved_archive_binds_layers_config_and_exact_archive_bytes() -> Result {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("image.tar");
    let (_, inspected, config) = content_fixture();
    saved(&path, "config.json", &config)?;
    let material = images::archive_material(&inspected, &path)?;
    assert_eq!(material["archive_digest"], util::hash(&path)?);
    assert_eq!(
        material["config_digest"],
        format!("sha256:{}", util::digest(&config))
    );
    let mut wrong = inspected;
    wrong["RootFS"]["Layers"] = json!([]);
    assert!(images::archive_material(&wrong, &path).is_err());
    Ok(())
}
#[test]
fn sbom_completeness_includes_development_and_workspace_dependencies() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    put(
        root,
        "Cargo.lock",
        "[[package]]\nname = \"fixture\"\nversion = \"1.0.0\"\nsource = \"registry+fixture\"\n",
    )?;
    put(
        root,
        "tests/compat/package-lock.json",
        &json!({"packages":{"":{},"node_modules/@example/dev":{"version":"2.0.0","dev":true}}})
            .to_string(),
    )?;
    let cargo = json!({"purl":"pkg:cargo/fixture@1.0.0"});
    let npm = json!({"purl":"pkg:npm/%40example/dev@2.0.0"});
    assert!(sbom::source_complete(root, std::slice::from_ref(&cargo)).is_err());
    sbom::source_complete(root, &[cargo, npm])
}
#[test]
fn empty_or_missing_sbom_formats_fail() -> Result {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    put(root, "source.cdx.json", "{\"components\":[]}")?;
    put(root, "source.spdx.json", "{\"packages\":[]}")?;
    assert!(sbom::validate_output(root, "source").is_err());
    Ok(())
}
#[test]
fn image_inventory_requires_pins_including_frontend_and_compose() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    for text in [
        "FROM alpine:latest\n".into(),
        "  from alpine:latest\n".into(),
        "FROM --platform=linux/amd64 alpine:latest\n".into(),
        format!("# syntax=docker/dockerfile:latest\nFROM {}\n", pin()),
    ] {
        put(root, "Dockerfile", &text)?;
        assert!(security::inventory(root).is_err());
    }
    put(
        root,
        "Dockerfile",
        &format!("FROM {} AS build\nFROM build AS tests\n", pin()),
    )?;
    assert_eq!(security::inventory(root)?.len(), 1);
    put(
        root,
        "docker-compose.test.yml",
        "services:\n  test:\n    image: 'alpine:latest'\n",
    )?;
    assert!(security::inventory(root).is_err());
    put(
        root,
        "docker-compose.test.yml",
        &format!("services:\n  test:\n    image: {}\n", pin()),
    )?;
    assert!(security::inventory(root)?[&pin()].contains("docker-compose.test.yml"));
    Ok(())
}
#[test]
fn repository_inventory_covers_all_active_images_without_retired_scanner() -> Result {
    let images = security::inventory(&xtask::root())?;
    assert_eq!(images.len(), 9);
    assert!(images.keys().all(|image| {
        !image.contains("trivy")
            && !image.starts_with("couchdb:")
            && !image.starts_with("golang:")
            && !image.starts_with("cgr.dev/chainguard/git:")
    }));
    assert!(images.contains_key(xtask::grype::GRYPE));
    for pin in [
        security::GITLEAKS,
        security::HELPER,
        sbom::SYFT,
        deployment::KIND,
    ] {
        assert!(images.contains_key(pin), "{pin}");
    }
    Ok(())
}
#[test]
fn scanners_use_caller_identity_bounded_readonly_root_and_no_socket() {
    let args = security::sandbox_args("unique-owned-container");
    let after = |flag: &str| args[args.iter().position(|v| v == flag).unwrap() + 1].as_str();
    assert_eq!(after("--user"), util::uid_gid());
    assert_eq!(after("--cap-drop"), "ALL");
    assert_eq!(after("--pids-limit"), "128");
    assert_eq!(after("--memory"), "3g");
    assert_eq!(after("--cpus"), "2");
    assert!(
        args.contains(&"--read-only".into())
            && args.contains(&"HOME=/tmp".into())
            && args.contains(&"no-new-privileges".into())
    );
    assert!(after("--tmpfs").contains("/tmp:rw,noexec,nosuid,nodev"));
    assert!(after("--tmpfs").contains("size=1536m"));
    assert!(
        !args
            .iter()
            .any(|v| v.contains("docker.sock") || v.contains("ignore-unfixed"))
    );
}
#[test]
fn history_snapshot_excludes_ignored_canaries_credentials_and_detached_worktree() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    put(root, ".gitignore", ".env\ndata/\n.work/\n")?;
    put(root, "Cargo.lock", "# Public fixture\n")?;
    put(root, ".env", "SYNTHETIC_CANARY=not-a-real-secret\n")?;
    put(root, "data/canary.txt", "synthetic only")?;
    commit(root)?;
    util::quiet(
        &mut util::cmd("git", &["checkout", "--detach", "-q"], root),
        30,
    )?;
    put(root, "Cargo.lock", "# Public detached fixture\n")?;
    commit(root)?;
    let out = tempfile::tempdir()?;
    let source = out.path().join("source");
    fs::create_dir(&source)?;
    util::copy_public_sources(root, &source)?;
    assert!(!source.join(".env").exists() && !source.join("data").exists());
    let mirror = out.path().join("history.git");
    security::history_snapshot(root, &mirror)?;
    assert!(mirror.join("HEAD").is_file());
    assert!(!mirror.join(".env").exists());
    let gitdir = mirror.to_str().ok_or("Invalid mirror path")?;
    assert!(
        util::output(
            &mut util::cmd(
                "git",
                &["--git-dir", gitdir, "config", "--get", "remote.origin.url"],
                root
            ),
            30
        )
        .is_err()
    );
    assert_eq!(
        util::text(
            &mut util::cmd(
                "git",
                &["--git-dir", gitdir, "show", "HEAD:Cargo.lock"],
                root
            ),
            30
        )?,
        "# Public detached fixture"
    );
    assert!(!mirror.join("objects/info/alternates").exists());
    Ok(())
}
#[test]
fn source_stage_rejects_symlinked_input() -> Result {
    let temp = fixture()?;
    symlink(
        temp.path().join("README.md"),
        temp.path().join("source-link"),
    )?;
    let out = tempfile::tempdir()?;
    assert!(util::copy_public_sources(temp.path(), out.path()).is_err());
    Ok(())
}
#[test]
fn scan_validation_rejects_vacuous_stale_wrong_image_and_unknown_schema() {
    for field in [
        "empty",
        "stale",
        "substitution",
        "identity",
        "severity",
        "missing",
    ] {
        let (mut catalog, mut report) = support::fixture();
        match field {
            "empty" => catalog["artifacts"] = json!([]),
            "stale" => {
                report["descriptor"]["timestamp"] =
                    json!((Utc::now() - Duration::days(2)).to_rfc3339())
            }
            "substitution" => report["source"]["target"] = json!("other"),
            "identity" => catalog["source"]["metadata"]["imageID"] = json!("tag"),
            "severity" => report["matches"] = json!([support::finding("NEW_UNRECOGNIZED")]),
            "missing" => {
                report.as_object_mut().unwrap().remove("matches");
            }
            _ => unreachable!(),
        }
        assert!(
            grype::image_subject(&catalog)
                .and_then(|_| grype::validate_report(&catalog, &report, Utc::now()))
                .is_err(),
            "{field}"
        );
    }
}
#[test]
fn low_and_unknown_findings_are_retained_not_waived() -> Result {
    let (catalog, mut report) = support::fixture();
    report["matches"] = json!([support::finding("Low"), support::finding("Unknown")]);
    assert_eq!(
        grype::validate_report(&catalog, &report, Utc::now())?.len(),
        2
    );
    for time in ["2026-10-23T00:00:00", "invalid"] {
        assert!(evidence::fresh(time, Utc::now()).is_err());
    }
    Ok(())
}
#[test]
fn command_timeout_reaps_owned_child() {
    assert!(util::quiet(std::process::Command::new("sleep").arg("30"), 0).is_err());
}
#[test]
fn evidence_rejects_symlinks_devices_oversized_files() -> Result {
    let temp = tempfile::tempdir()?;
    put(temp.path(), "value", "abc")?;
    symlink(temp.path().join("value"), temp.path().join("link"))?;
    assert!(util::read(&temp.path().join("link"), 10).is_err());
    assert!(util::read(&temp.path().join("value"), 2).is_err());
    assert!(util::read(Path::new("/dev/null"), 10).is_err());
    Ok(())
}
#[test]
fn writer_fencing_requires_failure_and_classified_error_on_either_stream() {
    for (out, err) in [
        (b"another writer owns".as_slice(), b"".as_slice()),
        (b"".as_slice(), b"another writer owns".as_slice()),
    ] {
        assert!(deployment::writer_denied(&util::Captured {
            success: false,
            stdout: out.to_vec(),
            stderr: err.to_vec()
        }));
        assert!(!deployment::writer_denied(&util::Captured {
            success: true,
            stdout: out.to_vec(),
            stderr: err.to_vec()
        }));
    }
    assert!(!deployment::writer_denied(&util::Captured {
        success: false,
        stdout: vec![],
        stderr: b"unrelated failure".to_vec()
    }));
}
#[test]
fn kube_commands_always_use_disposable_config_without_touching_sentinel() -> Result {
    let temp = tempfile::tempdir()?;
    let sentinel = temp.path().join("operator-config");
    fs::write(&sentinel, "synthetic sentinel")?;
    let disposable = temp.path().join("disposable-kubeconfig");
    for program in ["kind", "kubectl"] {
        let c = deployment::fenced_command(temp.path(), &disposable, program, &["version"]);
        assert!(
            c.get_envs()
                .any(|(key, value)| key == "KUBECONFIG" && value == Some(disposable.as_os_str()))
        );
        let args = security::recorded_command(&c);
        if program == "kubectl" {
            assert_eq!(&args[..2], &["--kubeconfig", disposable.to_str().unwrap()]);
        }
    }
    assert_eq!(fs::read_to_string(sentinel)?, "synthetic sentinel");
    Ok(())
}
#[test]
fn restart_waits_for_ready_container_not_merely_running_pod() -> Result {
    let temp = tempfile::tempdir()?;
    let config = temp.path().join("kubeconfig");
    let command = deployment::pod_ready_command(temp.path(), &config);
    let args = security::recorded_command(&command);
    assert!(args.contains(&"--for=condition=Ready".into()));
    assert!(
        !args
            .iter()
            .any(|arg| arg.contains("phase") || arg.contains("Running"))
    );
    assert_eq!(args[0], "--kubeconfig");
    assert_eq!(args[1], config.to_str().unwrap());
    Ok(())
}
#[test]
fn client_fixture_rejects_non_loopback_s3_and_relocates_state() -> Result {
    let temp = tempfile::tempdir()?;
    for endpoint in [
        "https://provider.invalid",
        "http://localhost:9000",
        "http://127.1:9000",
        "http://2130706433:9000",
        "http://0x7f000001:9000",
        "http://127.0.0.1.provider.invalid:9000",
        "http://user:password@127.0.0.1:9000",
    ] {
        let text = format!(
            "listen='127.0.0.1:1'\nmetadata_dir='/real'\n[storage]\nkind='s3'\nendpoint='{endpoint}'\n"
        );
        assert!(clients::config(&text, temp.path(), 1234, false, true).is_err());
    }
    let value: toml::Value = toml::from_str(&clients::config(
        "listen='old'\nmetadata_dir='/real'\n[storage]\nkind='filesystem'\nroot='/real'\n",
        temp.path(),
        1234,
        false,
        false,
    )?)?;
    assert_eq!(value["listen"].as_str(), Some("127.0.0.1:1234"));
    assert_eq!(value["http"]["burst"].as_integer(), Some(1024));
    assert!(
        value["storage"]["root"]
            .as_str()
            .unwrap()
            .starts_with(temp.path().to_str().unwrap())
    );
    Ok(())
}
#[test]
fn benchmark_memory_samples_parse_units() {
    assert_eq!(clients::memory_bytes("1.5MiB / 2GiB"), Some(1572864));
    assert_eq!(clients::memory_bytes("invalid"), None);
}
#[test]
fn aggregate_fails_closed_on_any_missing_skipped_canceled_or_failed_job() -> Result {
    let good = json!({"rust":"success","build":"success","security":"success","integration":"success","sbom":"success"});
    policy::require_jobs(&good)?;
    for status in ["failure", "skipped", "cancelled", "unknown", ""] {
        let mut value = good.clone();
        value["security"] = json!(status);
        assert!(policy::require_jobs(&value).is_err());
    }
    let mut value = good.clone();
    value.as_object_mut().unwrap().remove("sbom");
    assert!(policy::require_jobs(&value).is_err());
    let mut value = good;
    value["extra"] = json!("success");
    assert!(policy::require_jobs(&value).is_err());
    Ok(())
}
#[test]
fn unconfigured_and_deferred_policy_never_authorize_release() -> Result {
    assert!(
        policy::readiness(&util::json(
            &xtask::root().join(".github/security-readiness.json")
        )?)
        .is_err()
    );
    assert!(policy::codeowners("* @PRJXAI/unapproved", &["@PRJXAI/approved".into()]).is_err());
    assert!(policy::codeowners("src/ @PRJXAI/approved", &["@PRJXAI/approved".into()]).is_err());
    Ok(())
}
#[test]
fn public_summary_never_copies_canaries_or_raw_fields() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    fs::create_dir(root.join(".work"))?;
    put(root, "Dockerfile", &format!("FROM {}\n", pin()))?;
    let (catalog, mut report) = support::fixture();
    report["CANARY"] = json!("SYNTHETIC_PRIVATE_CANARY");
    support::write_receipt(&root.join(".work/sbom"), "runtime", &catalog, &report)?;
    put(
        root,
        ".work/security/gitleaks.json",
        "[{\"Secret\":\"SYNTHETIC_PRIVATE_CANARY\",\"Match\":\"private\",\"Author\":\"private\"}]",
    )?;
    supply_sbom::public_summary(root, &"a".repeat(40))?;
    let published = fs::read_to_string(root.join(".work/public-security/summary.json"))?;
    assert!(
        !published.contains("SYNTHETIC_PRIVATE_CANARY")
            && !published.contains("Author")
            && !published.contains("Match")
    );
    assert!(published.contains("error") && published.contains("fail"));
    assert!(supply_sbom::public_summary(root, &"a".repeat(40)).is_err());
    Ok(())
}
#[test]
fn first_party_automation_is_rust_and_shell_is_only_launchers() -> Result {
    let root = xtask::root();
    for folder in ["src", "xtask", "scripts", "tests", ".github"] {
        for item in walkdir::WalkDir::new(root.join(folder))
            .into_iter()
            .filter_entry(|e| {
                !matches!(
                    e.file_name().to_str(),
                    Some("target" | "node_modules" | "__pycache__")
                )
            })
        {
            let item = item?;
            if item.file_type().is_file() {
                assert!(
                    item.path().extension().is_none_or(|e| e != "py"),
                    "Forbidden first-party language: {}",
                    item.path().display()
                );
            }
        }
    }
    for entry in fs::read_dir(root.join("scripts"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "sh") {
            let text = fs::read_to_string(&path)?;
            let task = path.file_stem().unwrap().to_str().unwrap();
            assert_eq!(
                text,
                format!(
                    "#!/usr/bin/env bash\nset -euo pipefail\ncd \"$(dirname \"$0\")/..\"\nexec cargo xtask {task} \"$@\"\n"
                )
            );
        }
    }
    let workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))?;
    assert!(
        !regex::Regex::new(r"(?im)^\s*(?:-\s*run:\s*)?(?:exec\s+)?python(?:[0-9.]+)?(?:\s|$)")?
            .is_match(&workflow)
    );
    Ok(())
}

#[test]
fn evidence_rejects_duplicate_keys_and_structural_bombs() -> Result {
    assert!(util::strict_json(br#"{"status":"pass","status":"fail"}"#).is_err());
    assert!(util::strict_json(br#"{"nested":{"x":1,"x":2}}"#).is_err());
    assert!(
        util::strict_json(format!("[{}0]", "0,".repeat(util::STRUCTURAL_LIMIT + 1)).as_bytes())
            .is_err()
    );
    assert_eq!(
        util::strict_json(br#"{"string":"[\\\"{}]","number":2.5,"array":[null,true]}"#)?["number"],
        json!(2.5)
    );
    Ok(())
}
#[test]
fn local_ledger_keeps_target_specific_findings_and_never_approves_them() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    put(root, "Dockerfile", &format!("FROM {}\n", pin()))?;
    let output = supply_sbom::output(root, "linux/arm64")?;
    let (mut catalog, mut report) = support::fixture();
    let mut other = catalog["artifacts"][0].clone();
    other["id"] = json!("other");
    catalog["artifacts"].as_array_mut().unwrap().push(other);
    let mut one = support::finding("Unknown");
    one["artifact"]["locations"] = json!([{"path":"/bin/one"}]);
    let mut two = one.clone();
    two["artifact"]["id"] = json!("other");
    two["artifact"]["locations"] = json!([{"path":"/bin/two"}]);
    report["matches"] = json!([one, two]);
    support::write_receipt(&output, "image-00", &catalog, &report)?;
    let summary = json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"platform":"linux/arm64","images":[{"image":pin(),"receipt":"image-00.scan.json","status":"findings","findings":2}]});
    util::write_json(&output.join("summary.json"), &summary)?;
    supply_sbom::ledger(root, "linux/arm64", &"a".repeat(40))?;
    let ledger = util::json(&output.join("findings-ledger.json"))?;
    let findings = ledger["images"][0]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2);
    assert_ne!(findings[0]["id"], findings[1]["id"]);
    assert!(
        findings
            .iter()
            .all(|v| v["status"] == "under_investigation" && v["owner"].is_null())
    );
    for field in ["status", "findings", "image", "receipt"] {
        let mut bad = summary.clone();
        bad["images"][0][field] = if field == "findings" {
            json!(0)
        } else {
            json!("wrong")
        };
        util::write_json(&output.join("summary.json"), &bad)?;
        assert!(
            supply_sbom::ledger(root, "linux/arm64", &"a".repeat(40)).is_err(),
            "{field}"
        );
    }
    util::write_json(&output.join("summary.json"), &summary)?;
    report["descriptor"]["timestamp"] = json!((Utc::now() - Duration::days(2)).to_rfc3339());
    support::write_receipt(&output, "image-00", &catalog, &report)?;
    assert!(supply_sbom::ledger(root, "linux/arm64", &"a".repeat(40)).is_err());
    Ok(())
}
#[test]
fn archive_reader_rejects_symlink_and_device_inputs() -> Result {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("image.tar");
    let (_, _, config) = content_fixture();
    saved(&path, "config.json", &config)?;
    symlink(&path, temp.path().join("link.tar"))?;
    assert!(images::saved_config(&temp.path().join("link.tar")).is_err());
    assert!(images::saved_config(Path::new("/dev/null")).is_err());
    Ok(())
}
#[test]
fn static_elf_rejects_interpreter_and_invalid_bounds() -> Result {
    let mut elf = vec![0; 128];
    elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    images::verify_elf(&elf)?;
    elf[64..68].copy_from_slice(&3u32.to_le_bytes());
    assert!(images::verify_elf(&elf).is_err());
    elf[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(images::verify_elf(&elf).is_err());
    Ok(())
}

#[test]
fn repository_preflight_rejects_missing_review_bypass_and_spoofable_checks() -> Result {
    let branch = json!({"protected":true});
    let rules = json!([
        {"type":"pull_request","ruleset_id":7,"parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,"require_code_owner_review":true,"require_last_push_approval":true,"required_review_thread_resolution":true}},
        {"type":"required_status_checks","ruleset_id":7,"parameters":{"strict_required_status_checks_policy":true,"required_status_checks":[{"context":policy::REQUIRED_CHECK,"integration_id":15368}]}},
        {"type":"deletion","ruleset_id":7},{"type":"non_fast_forward","ruleset_id":7}
    ]);
    let rulesets = vec![json!({"id":7,"enforcement":"active","bypass_actors":[]})];
    let environment = json!({"can_admins_bypass":false,"protection_rules":[{"type":"required_reviewers","prevent_self_review":true,"reviewers":[{"type":"Team"}]}],"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}});
    let permissions =
        json!({"default_workflow_permissions":"read","can_approve_pull_request_reviews":false});
    policy::controls(&branch, &rules, &rulesets, &environment, &permissions)?;
    for kind in [
        "branch",
        "review",
        "check",
        "app",
        "strict",
        "ruleset",
        "bypass",
        "self",
        "admin",
        "environment",
        "permissions",
    ] {
        let (mut b, mut r, mut rs, mut e, mut p) = (
            branch.clone(),
            rules.clone(),
            rulesets.clone(),
            environment.clone(),
            permissions.clone(),
        );
        match kind {
            "branch" => b["protected"] = json!(false),
            "review" => r[0]["parameters"]["require_code_owner_review"] = json!(false),
            "check" => r[1]["parameters"]["required_status_checks"][0]["context"] = json!("other"),
            "app" => {
                r[1]["parameters"]["required_status_checks"][0]["integration_id"] = Value::Null
            }
            "strict" => r[1]["parameters"]["strict_required_status_checks_policy"] = json!(false),
            "ruleset" => rs.clear(),
            "bypass" => rs[0]["bypass_actors"] = json!([{"actor_id":1}]),
            "self" => e["protection_rules"][0]["prevent_self_review"] = json!(false),
            "admin" => e["can_admins_bypass"] = json!(true),
            "environment" => e["protection_rules"] = json!([]),
            "permissions" => p["default_workflow_permissions"] = json!("write"),
            _ => unreachable!(),
        }
        assert!(policy::controls(&b, &r, &rs, &e, &p).is_err(), "{kind}");
    }
    Ok(())
}
#[test]
fn closure_policy_rejects_waiver_missing_evidence_and_unowned_overrides() -> Result {
    let mut value = json!({"schema_version":1,"scope":{"framework":"owner-selected-test-framework","data_classification":"synthetic","deployment_profile":"test"},"reviewer_teams":["@PRJXAI/test-reviewers"],"milestones":{}});
    for n in 0..8 {
        value["milestones"][format!("M{n}")] =
            json!({"state":"verified","evidence_sha256":["a".repeat(64)]});
    }
    let teams = policy::readiness(&value)?;
    policy::codeowners("* @PRJXAI/test-reviewers\n", &teams)?;
    for state in ["deferred", "waived", "blocked", "in_progress"] {
        let mut bad = value.clone();
        bad["milestones"]["M4"]["state"] = json!(state);
        assert!(policy::readiness(&bad).is_err());
    }
    value["milestones"]["M2"]["evidence_sha256"] = json!([]);
    assert!(policy::readiness(&value).is_err());
    assert!(policy::codeowners("* @PRJXAI/test-reviewers\nsecurity/\n", &teams).is_err());
    Ok(())
}
