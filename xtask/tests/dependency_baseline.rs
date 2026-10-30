mod support;

fn private_baseline_policy(workflow: &str) -> bool {
    let Some(section) = workflow
        .split("\n  security:\n")
        .nth(1)
        .and_then(|s| s.split("\n  integration:\n").next())
    else {
        return false;
    };
    section.contains("      - name: Assemble private dependency baseline from bound image/build reports\n        if: always()\n        run: cargo xtask dependency-baseline --platform linux/amd64\n")
        && section.lines().map(str::trim).filter(|line|line.starts_with("path:")).collect::<Vec<_>>() == ["path: .work/public-security/"]
}
#[test]
fn ci_runs_baseline_on_failures_without_publishing_private_evidence() {
    let workflow = include_str!("../../.github/workflows/ci.yml");
    assert!(private_baseline_policy(workflow));
    assert!(!private_baseline_policy(&workflow.replace(
        "path: .work/public-security/",
        "path: .work/security/"
    )));
    assert!(!private_baseline_policy(&workflow.replace(
        "run: cargo xtask dependency-baseline --platform linux/amd64",
        "run: cargo xtask publish-security-summary --source-revision invalid"
    )));
}
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::{MetadataExt, symlink},
    path::Path,
};
use xtask::{Result, dependency_baseline, grype, sbom, supply_sbom, util};

fn fixture() -> Result<tempfile::TempDir> {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let image = format!("example/fixture:v1@sha256:{}", "a".repeat(64));
    fs::write(root.join("Dockerfile"), format!("FROM {image}\n"))?;
    let registry = supply_sbom::output(root, "linux/amd64")?;
    let (build_catalog, build_report) = support::fixture();
    let mut catalog = build_catalog.clone();
    let mut config: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(catalog["source"]["metadata"]["config"].as_str().unwrap())?,
    )?;
    config["architecture"] = json!("amd64");
    let bytes = serde_json::to_vec(&config)?;
    catalog["source"]["metadata"]["config"] =
        json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
    catalog["source"]["metadata"]["imageID"] = json!(format!("sha256:{}", util::digest(&bytes)));
    let mut report = build_report.clone();
    report["source"]["target"] = catalog["source"]["metadata"].clone();
    support::write_receipt(&registry, "image-00", &catalog, &report)?;
    util::write_json(
        &registry.join("summary.json"),
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"platform":"linux/amd64","cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"images":[{"image":image,"receipt":"image-00.scan.json","findings":0,"status":"pass"}]}),
    )?;
    let output = root.join(".work/sbom");
    for name in ["runtime", "builder"] {
        let mut report = build_report.clone();
        if name == "builder" {
            let mut one = support::finding("Unknown");
            one["artifact"]["locations"] = json!([{"path":"/one"}]);
            let mut two = one.clone();
            two["artifact"]["locations"] = json!([{"path":"/two"}]);
            report["matches"] = json!([one]);
            report["ignoredMatches"] = json!([{"match":two}]);
        }
        support::write_receipt(&output, name, &build_catalog, &report)?;
    }
    let mut source = build_catalog.clone();
    source["source"] = json!({"type":"directory","metadata":{"path":"/source"}});
    let mut report = build_report.clone();
    report["source"] = json!({"type":"directory","target":"/source"});
    util::write_json(&output.join("source.syft.json"), &source)?;
    util::write_json(&output.join("source.grype.json"), &report)?;
    util::write_json(
        &output.join("source.scan.json"),
        &json!({"kind":"syft-grype-content-evidence","schema_version":1,"CreatedAt":Utc::now().to_rfc3339(),"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"Metadata":{"type":"directory"},"findings":0,"sbom":{"path":"source.syft.json","digest":util::hash(&output.join("source.syft.json"))?},"report":{"path":"source.grype.json","digest":util::hash(&output.join("source.grype.json"))?}}),
    )?;
    let mut artifacts = Vec::new();
    for name in ["source", "runtime", "builder"] {
        for format in ["syft", "cdx", "spdx"] {
            let path = format!("{name}.{format}.json");
            if format != "syft" {
                fs::write(output.join(&path), "public synthetic format fixture")?;
            }
            artifacts.push(json!({"path":path,"digest":util::hash(&output.join(&path))?}));
        }
    }
    fs::write(
        output.join("native-toolchain.txt"),
        "public native identity fixture",
    )?;
    artifacts.push(json!({"path":"native-toolchain.txt","digest":util::hash(&output.join("native-toolchain.txt"))?}));
    let subject = grype::image_subject(&build_catalog)?;
    let image = json!({"architecture":"arm64","os":"linux","config_digest":subject["ImageID"],"layers":subject["DiffIDs"],"archive_digest":format!("sha256:{}","c".repeat(64)),"image_id":subject["ImageID"]});
    util::write_json(
        &output.join("materials.json"),
        &json!({"schema_version":1,"generator_image":sbom::SYFT,"source_revision":"a".repeat(40),"source_tree_digest":format!("sha256:{}","d".repeat(64)),"working_tree_dirty":true,"artifacts":artifacts,"images":{"runtime":image,"builder":image}}),
    )?;
    Ok(temp)
}
fn mutate(root: &Path, path: &str, change: impl FnOnce(&mut Value)) -> Result {
    let path = root.join(path);
    let mut v = util::json(&path)?;
    change(&mut v);
    util::write_json(&path, &v)
}
#[test]
fn baseline_preserves_mixed_platforms_original_revision_and_every_suppressed_location() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    dependency_baseline::generate(root, "linux/amd64")?;
    let path = root.join(".work/security/dependency-baseline.json");
    assert_eq!(fs::metadata(&path)?.mode() & 0o777, 0o600);
    let baseline = util::json(&path)?;
    assert_eq!(baseline["assets"].as_array().unwrap().len(), 4);
    assert_eq!(baseline["assets"][0]["subject"]["architecture"], "amd64");
    let builder = &baseline["assets"][3];
    assert_eq!(builder["subject"]["architecture"], "arm64");
    assert_eq!(baseline["build_source"]["revision"], "a".repeat(40));
    assert_eq!(baseline["build_source"]["dirty"], true);
    assert_eq!(builder["findings"], 2);
    assert_eq!(builder["suppressed"], 1);
    assert_eq!(builder["counts"]["Unknown"], 2);
    assert_eq!(builder["groups"].as_array().unwrap().len(), 1);
    let group = &builder["groups"][0];
    assert_eq!(group["count"], 2);
    assert_eq!(group["suppressed"], 1);
    assert_eq!(group["occurrences"][0]["locations"][0]["path"], "/one");
    assert_eq!(group["occurrences"][1]["locations"][0]["path"], "/two");
    assert_eq!(group["status"], "under_investigation");
    assert!(group["owner"].is_null());
    assert_eq!(builder["archive_bytes_reverified"], false);
    assert_eq!(baseline["authorization"], "none");
    assert!(dependency_baseline::generate(root, "linux/amd64").is_err());
    Ok(())
}
#[test]
fn baseline_rejects_stale_substituted_missing_duplicate_and_wrong_platform_evidence() -> Result {
    for case in 0..10 {
        let temp = fixture()?;
        let root = temp.path();
        match case {
            0 => mutate(root, ".work/security/sbom-chain/amd64/summary.json", |v| {
                v["created_at"] = json!((Utc::now() - Duration::days(2)).to_rfc3339())
            })?,
            1 => mutate(root, ".work/security/sbom-chain/amd64/summary.json", |v| {
                v["images"][0]["findings"] = json!(1)
            })?,
            2 => mutate(root, ".work/sbom/materials.json", |v| {
                v["images"]["builder"]["architecture"] = json!("amd64")
            })?,
            3 => mutate(root, ".work/sbom/materials.json", |v| {
                v["source_revision"] = json!("bad")
            })?,
            4 => mutate(root, ".work/sbom/materials.json", |v| {
                v["artifacts"][1] = v["artifacts"][0].clone();
            })?,
            5 => {
                fs::remove_file(root.join(".work/sbom/builder.scan.json"))?;
            }
            6 => {
                fs::write(root.join(".work/sbom/native-toolchain.txt"), "changed")?;
            }
            7 => mutate(root, ".work/sbom/builder.grype.json", |v| {
                v["ignoredMatches"] = json!([])
            })?,
            8 => mutate(root, ".work/security/sbom-chain/amd64/summary.json", |v| {
                v["platform"] = json!("linux/arm64")
            })?,
            _ => mutate(root, ".work/sbom/materials.json", |v| {
                v["working_tree_dirty"] = json!("false")
            })?,
        }
        assert!(
            dependency_baseline::generate(root, "linux/amd64").is_err(),
            "case {case}"
        );
        assert!(
            !root
                .join(".work/security/dependency-baseline.json")
                .exists()
        );
    }
    Ok(())
}
#[test]
fn baseline_rejects_symlinked_reports_and_existing_destination_without_overwriting() -> Result {
    let temp = fixture()?;
    let root = temp.path();
    let report = root.join(".work/sbom/builder.grype.json");
    let original = root.join("original-report");
    fs::rename(&report, &original)?;
    symlink(&original, &report)?;
    assert!(dependency_baseline::generate(root, "linux/amd64").is_err());
    fs::remove_file(&report)?;
    fs::rename(original, &report)?;
    let output = root.join(".work/security/dependency-baseline.json");
    let sentinel = root.join("sentinel");
    fs::write(&sentinel, "unchanged")?;
    symlink(&sentinel, &output)?;
    assert!(dependency_baseline::generate(root, "linux/amd64").is_err());
    assert_eq!(fs::read_to_string(sentinel)?, "unchanged");
    Ok(())
}
