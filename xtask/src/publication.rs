//! Manually authorized, single-platform promotion of the tested CI archive.
//! Not deployment authorization or a regulated-use approval.
use crate::{Result, ensure, evidence, grype, images, policy, util};
use chrono::Utc;
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

pub const REPOSITORY: &str = "ghcr.io/prjxai/obsidian-sync";

pub fn context(value: &Value, revision: &str) -> Result<String> {
    ensure(
        policy::is_revision(revision)
            && value["event"] == "workflow_dispatch"
            && value["ref"] == "refs/heads/main"
            && value["repository"] == policy::REPOSITORY
            && value["workflow_ref"]
                == "PRJXAI/obsidian-sync/.github/workflows/ci.yml@refs/heads/main"
            && value["sha"] == revision
            && value["required_ci"] == "success"
            && value["redistribution_approved_sha"] == revision,
        "Manual source-bound publication approval and Required CI required",
    )?;
    let number = |key: &str| -> Result<&str> {
        let s = value[key].as_str().ok_or("Missing CI run identity")?;
        ensure(
            !s.is_empty()
                && s.len() <= 20
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u64>().is_ok_and(|v| v > 0),
            "Invalid CI run identity",
        )?;
        Ok(s)
    };
    Ok(format!(
        "sha-{revision}-run-{}-{}-amd64",
        number("run_id")?,
        number("run_attempt")?
    ))
}

pub fn bound_source(
    materials: &Value,
    archive: &Value,
    config: &Value,
    inspected: &Value,
    revision: &str,
) -> Result {
    ensure(
        materials["schema_version"] == 1
            && materials["source_revision"] == revision
            && materials["working_tree_dirty"] == false,
        "Clean source-bound materials required",
    )?;
    let expected = &materials["images"]["runtime"];
    for key in [
        "archive_digest",
        "config_digest",
        "layers",
        "os",
        "architecture",
    ] {
        ensure(
            expected[key] == archive[key] && !archive[key].is_null(),
            "Runtime archive differs from original materials",
        )?;
    }
    ensure(
        archive["os"] == "linux"
            && archive["architecture"] == "amd64"
            && config["os"] == "linux"
            && config["architecture"] == "amd64"
            && config["config"]["Labels"]["org.opencontainers.image.revision"] == revision
            && inspected["Config"]["Labels"]["org.opencontainers.image.revision"] == revision
            && inspected["Config"]["User"] == "65532:65532"
            && inspected["Config"]["Entrypoint"] == json!(["/server"]),
        "Only the source-bound tested Linux amd64 runtime may be published",
    )
}

fn create(path: &Path, bytes: &[u8]) -> Result {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn publish(root: &Path, revision: &str) -> Result {
    let env = |key: &str| std::env::var(key).unwrap_or_default();
    let tag = context(
        &json!({"event":env("GITHUB_EVENT_NAME"),"ref":env("GITHUB_REF"),"repository":env("GITHUB_REPOSITORY"),"workflow_ref":env("GITHUB_WORKFLOW_REF"),"sha":env("GITHUB_SHA"),"required_ci":env("PUBLISH_REQUIRED_CI_RESULT"),"redistribution_approved_sha":env("PUBLISH_REDISTRIBUTION_APPROVED_SHA"),"run_id":env("GITHUB_RUN_ID"),"run_attempt":env("GITHUB_RUN_ATTEMPT")}),
        revision,
    )?;
    ensure(
        util::text(&mut util::cmd("git", &["rev-parse", "HEAD"], root), 30)? == revision
            && util::output(
                &mut util::cmd(
                    "git",
                    &["status", "--porcelain", "--untracked-files=normal"],
                    root,
                ),
                30,
            )?
            .is_empty(),
        "Publication checkout changed",
    )?;
    util::local_docker(root)?;
    let archive_path = root.join(".work/ci-images/runtime.tar");
    let materials = util::json(&root.join(".work/sbom/materials.json"))?;
    let config_bytes = images::saved_config(&archive_path)?;
    let config = util::strict_json(&config_bytes)?;
    let inspected = images::inspect(root, "obsidian-sync:local")?;
    let archive = images::archive_material(&inspected, &archive_path)?;
    bound_source(&materials, &archive, &config, &inspected, revision)?;
    // Fresh matching is done before registry login. Revalidate all receipt/raw
    // evidence now; never transfer a raw scanner report through public artifacts.
    let receipt_path = root.join(".work/sbom/runtime.scan.json");
    let report = grype::receipt(&receipt_path, Utc::now())?;
    let native_id = images::verify_content(&report, &inspected, &config_bytes, Utc::now())?;
    // Re-export the actual loaded immutable image too: original-archive bytes
    // alone cannot establish the daemon's current configuration identity.
    images::verify_release(root, &native_id, &receipt_path)?;
    evidence::fresh(
        report["CreatedAt"].as_str().ok_or("Missing scan time")?,
        Utc::now(),
    )?;
    let destination = root.join(".work/published-application");
    fs::DirBuilder::new().mode(0o700).create(&destination)?;
    create(
        &destination.join("attempt.private.json"),
        &serde_json::to_vec(
            &json!({"schema":1,"phase":"validated-before-push","source_revision":revision,"tag":tag,"archive":archive,"receipt_sha256":util::hash(&receipt_path)?}),
        )?,
    )?;
    let reference = format!("{REPOSITORY}:{tag}");
    util::check_cancelled()?;
    util::output(
        &mut util::cmd("docker", &["image", "tag", &native_id, &reference], root),
        30,
    )?;
    util::check_cancelled()?;
    util::logged(
        &mut util::cmd(
            "docker",
            &["image", "push", "--platform", "linux/amd64", &reference],
            root,
        ),
        &destination.join("push.private.log"),
        900,
    )?;
    let descriptor = util::strict_json(&util::output(
        &mut util::cmd(
            "docker",
            &[
                "buildx",
                "imagetools",
                "inspect",
                "--format",
                "{{json .Manifest}}",
                &reference,
            ],
            root,
        ),
        120,
    )?)?;
    let digest = descriptor["digest"]
        .as_str()
        .filter(|v| images::is_digest(v))
        .ok_or("Missing published manifest digest")?;
    let immutable = format!("{REPOSITORY}@{digest}");
    let bytes = util::output(
        &mut util::cmd(
            "docker",
            &["buildx", "imagetools", "inspect", "--raw", &immutable],
            root,
        ),
        120,
    )?;
    let manifest = util::strict_json(&bytes)?;
    ensure(
        format!("sha256:{}", util::digest(&bytes)) == digest
            && manifest["schemaVersion"] == 2
            && manifest.get("manifests").is_none()
            && manifest["config"]["digest"] == archive["config_digest"]
            && manifest["layers"].as_array().is_some_and(|v| !v.is_empty()),
        "Published runtime manifest differs from tested configuration",
    )?;
    create(
        &destination.join("subjects.checksums"),
        format!("{}  {REPOSITORY}\n", digest.trim_start_matches("sha256:")).as_bytes(),
    )?;
    create(
        &destination.join("release.json"),
        &serde_json::to_vec_pretty(
            &json!({"schema":1,"source_revision":revision,"repository":REPOSITORY,"manifest_digest":digest,"platform":"linux/amd64","tag":tag,"runtime_findings":0,"scope":"image publication, not deployment approval"}),
        )?,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const REV: &str = "0123456789abcdef0123456789abcdef01234567";
    #[test]
    fn only_explicit_successful_main_dispatch_can_reach_publication() {
        let valid = json!({"event":"workflow_dispatch","ref":"refs/heads/main","repository":policy::REPOSITORY,"workflow_ref":"PRJXAI/obsidian-sync/.github/workflows/ci.yml@refs/heads/main","sha":REV,"required_ci":"success","redistribution_approved_sha":REV,"run_id":"123","run_attempt":"1"});
        assert_eq!(
            context(&valid, REV).unwrap(),
            format!("sha-{REV}-run-123-1-amd64")
        );
        for key in valid.as_object().unwrap().keys() {
            let mut bad = valid.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(context(&bad, REV).is_err());
        }
        for (key, value) in [
            ("event", "push"),
            ("event", "pull_request"),
            ("ref", "refs/heads/other"),
            ("required_ci", "failure"),
            ("required_ci", "skipped"),
            ("required_ci", "cancelled"),
            ("repository", "foreign"),
            ("sha", "foreign"),
            ("workflow_ref", "foreign"),
            ("redistribution_approved_sha", "foreign"),
            ("run_id", "0"),
            ("run_id", "../bad"),
            ("run_attempt", "18446744073709551616"),
        ] {
            let mut bad = valid.clone();
            bad[key] = json!(value);
            assert!(context(&bad, REV).is_err());
        }
    }
    #[test]
    fn substituted_dirty_cross_platform_and_changed_runtime_materials_block() {
        let archive = json!({"archive_digest":"archive","config_digest":"config","layers":["layer"],"os":"linux","architecture":"amd64"});
        let config = json!({"os":"linux","architecture":"amd64","config":{"Labels":{"org.opencontainers.image.revision":REV}}});
        let inspected = json!({"Config":{"User":"65532:65532","Entrypoint":["/server"],"Labels":{"org.opencontainers.image.revision":REV}}});
        let materials = json!({"schema_version":1,"source_revision":REV,"working_tree_dirty":false,"images":{"runtime":archive}});
        assert!(bound_source(&materials, &archive, &config, &inspected, REV).is_ok());
        for (path, value) in [
            ("/source_revision", json!("foreign")),
            ("/working_tree_dirty", json!(true)),
            ("/images/runtime/archive_digest", json!("foreign")),
            ("/images/runtime/config_digest", json!("foreign")),
            ("/images/runtime/layers", json!(["foreign"])),
            ("/images/runtime/architecture", json!("arm64")),
        ] {
            let mut bad = materials.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(bound_source(&bad, &archive, &config, &inspected, REV).is_err());
        }
        let mut bad = inspected.clone();
        bad["Config"]["User"] = json!("0");
        assert!(bound_source(&materials, &archive, &config, &bad, REV).is_err());
        let mut bad = config.clone();
        bad["architecture"] = json!("arm64");
        assert!(bound_source(&materials, &archive, &bad, &inspected, REV).is_err());
    }
}
