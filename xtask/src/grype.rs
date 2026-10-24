//! Syft catalogues bytes; Grype matches a bounded immutable SBOM, offline.
use crate::{Result, ensure, images, sbom, security, util};
use base64::Engine;
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path, process::Command};

pub const GRYPE: &str = "anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea";
pub const SEVERITIES: [&str; 6] = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];

fn command(root: &Path, container: &util::Container, cache: &Path, offline: bool) -> Command {
    let mut c = util::cmd("docker", &[], root);
    c.args(security::sandbox_args(&container.name));
    if offline {
        c.args(["--network", "none"]);
    }
    c.args([
        "--env",
        "GRYPE_DB_CACHE_DIR=/cache",
        "--env",
        "GRYPE_DB_AUTO_UPDATE=false",
        "--env",
        "GRYPE_DB_VALIDATE_AGE=true",
        "--env",
        "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=72h",
        "--env",
        "GRYPE_CHECK_FOR_APP_UPDATE=false",
        "--env",
        "GRYPE_INCLUDE_MATCHER_SUPPRESSIONS=true",
        "--volume",
        &format!(
            "{}:/cache{}",
            cache.display(),
            if offline { ":ro" } else { "" }
        ),
    ]);
    c
}
pub fn database(root: &Path, cache: &Path, output: &Path) -> Result<Value> {
    fs::create_dir_all(cache)?;
    fs::create_dir_all(output)?;
    let container = util::Container::new(root, "sync-grype-db");
    let mut c = command(root, &container, cache, false);
    c.args([GRYPE, "db", "update"]);
    util::logged(&mut c, &output.join("grype-db-update.log"), 600)?;
    let container = util::Container::new(root, "sync-grype-status");
    let mut c = command(root, &container, cache, true);
    c.args([GRYPE, "db", "status", "--output", "json"]);
    let bytes = util::output(&mut c, 60)?;
    let status = util::strict_json(&bytes)?;
    valid_db(&status, Utc::now())?;
    fs::write(output.join("grype-db.json"), bytes)?;
    Ok(status)
}
pub fn valid_db(status: &Value, now: DateTime<Utc>) -> Result {
    ensure(
        status["valid"] == true && status["schemaVersion"] == "v6.1.10",
        "Invalid/unsupported Grype DB",
    )?;
    let built = DateTime::parse_from_rfc3339(status["built"].as_str().ok_or("Missing DB time")?)?;
    ensure(
        (-300..=72 * 3600).contains(&now.signed_duration_since(built).num_seconds()),
        "Stale/future Grype DB",
    )
}
pub fn validate_catalog(catalog: &Value) -> Result {
    ensure(
        catalog["schema"]["version"] == "16.1.11"
            && catalog["descriptor"]["name"] == "syft"
            && catalog["descriptor"]["version"] == "1.55.0",
        "Unsupported cataloger/schema",
    )?;
    let artifacts = catalog["artifacts"].as_array().ok_or("Missing catalog")?;
    ensure(!artifacts.is_empty(), "Vacuous catalog")?;
    let mut ids = BTreeSet::new();
    for artifact in artifacts {
        let id = artifact["id"].as_str().ok_or("Missing package ID")?;
        ensure(
            !id.is_empty()
                && ids.insert(id)
                && artifact["name"].is_string()
                && artifact["type"].is_string(),
            "Invalid/duplicate catalog artifact",
        )?;
    }
    ensure(
        catalog["source"].is_object()
            && catalog["source"]["type"]
                .as_str()
                .is_some_and(|v| ["image", "directory"].contains(&v)),
        "Missing/unsupported SBOM source",
    )
}
pub fn image_subject(catalog: &Value) -> Result<Value> {
    validate_catalog(catalog)?;
    ensure(catalog["source"]["type"] == "image", "Expected image SBOM")?;
    let metadata = &catalog["source"]["metadata"];
    let encoded = metadata["config"]
        .as_str()
        .ok_or("Missing saved image config")?;
    ensure(
        encoded.len() <= 2 * 1024 * 1024,
        "Oversized image configuration",
    )?;
    let config = base64::engine::general_purpose::STANDARD.decode(encoded)?;
    let digest = format!("sha256:{}", util::digest(&config));
    ensure(
        metadata["imageID"] == digest,
        "Catalog config identity mismatch",
    )?;
    let config = util::strict_json(&config)?;
    let layers = &config["rootfs"]["diff_ids"];
    ensure(
        layers.as_array().is_some_and(|v| {
            !v.is_empty() && v.iter().all(|v| v.as_str().is_some_and(images::is_digest))
        }),
        "Missing image layer identity",
    )?;
    Ok(
        json!({"ImageID":digest,"DiffIDs":layers,"os":config["os"],"architecture":config["architecture"]}),
    )
}
pub fn validate_report(catalog: &Value, report: &Value, now: DateTime<Utc>) -> Result<Vec<Value>> {
    validate_catalog(catalog)?;
    ensure(
        report["descriptor"]["name"] == "grype" && report["descriptor"]["version"] == "0.121.0",
        "Unsupported scanner",
    )?;
    crate::evidence::fresh(
        report["descriptor"]["timestamp"]
            .as_str()
            .ok_or("Missing scan time")?,
        now,
    )?;
    valid_db(&report["descriptor"]["db"]["status"], now)?;
    ensure(
        report["descriptor"]["configuration"]["include-matcher-suppressions"] == true,
        "Matcher suppression accounting required",
    )?;
    let source_matches = report["source"]["target"] == catalog["source"]["metadata"]
        || (catalog["source"]["type"] == "directory"
            && report["source"]["target"] == catalog["source"]["metadata"]["path"]);
    ensure(
        report["source"]["type"] == catalog["source"]["type"] && source_matches,
        "Grype/SBOM source substitution",
    )?;
    let ids = catalog["artifacts"]
        .as_array()
        .ok_or("Missing artifacts")?
        .iter()
        .filter_map(|v| v["id"].as_str())
        .collect::<BTreeSet<_>>();
    let mut matches = report["matches"]
        .as_array()
        .ok_or("Missing matches; not a clean report")?
        .clone();
    if let Some(ignored) = report.get("ignoredMatches") {
        for value in ignored.as_array().ok_or("Invalid ignored matches")? {
            matches.push(value.get("match").unwrap_or(value).clone());
        }
    }
    for value in &matches {
        ensure(
            value["vulnerability"]["id"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
                && value["vulnerability"]["severity"]
                    .as_str()
                    .is_some_and(|s| SEVERITIES.contains(&s))
                && value["artifact"]["id"]
                    .as_str()
                    .is_some_and(|id| ids.contains(id)),
            "Unknown severity/schema or foreign package match",
        )?;
    }
    Ok(matches)
}
pub fn scan(root: &Path, input: &Path, output: &Path, cache: &Path, name: &str) -> Result<usize> {
    ensure(
        name.bytes().all(|v| v.is_ascii_alphanumeric() || v == b'-'),
        "Invalid report name",
    )?;
    let catalog = util::json(input)?;
    validate_catalog(&catalog)?;
    let report = output.join(format!("{name}.grype.json"));
    let receipt = output.join(format!("{name}.scan.json"));
    for path in [&report, &receipt] {
        if path.symlink_metadata().is_ok() {
            fs::remove_file(path)?;
        }
    }
    let temporary = tempfile::Builder::new()
        .prefix("grype-output-")
        .tempdir_in(root.join(".work"))?;
    let container = util::Container::new(root, "sync-grype-sbom");
    let mut c = command(root, &container, cache, true);
    c.args([
        "--volume",
        &format!("{}:/input/sbom.json:ro", input.display()),
        "--volume",
        &format!("{}:/reports", temporary.path().display()),
        GRYPE,
        "sbom:/input/sbom.json",
        "--output",
        "json",
        "--file",
        &format!("/reports/{name}.grype.json"),
    ]);
    // No severity threshold, --only-fixed, VEX or ignored findings. Rust rejects
    // every match, including Unknown and Negligible, after a successful scan.
    util::logged(&mut c, &output.join(format!("{name}.grype.log")), 600)?;
    let bytes = util::read(
        &temporary.path().join(format!("{name}.grype.json")),
        util::JSON_LIMIT,
    )?;
    let raw = util::strict_json(&bytes)?;
    let findings = validate_report(&catalog, &raw, Utc::now())?;
    fs::write(&report, bytes)?;
    let relative = format!("{name}.syft.json");
    let saved = output.join(&relative);
    if input != saved {
        fs::write(&saved, util::read(input, util::JSON_LIMIT)?)?;
    }
    let subject = if catalog["source"]["type"] == "image" {
        image_subject(&catalog)?
    } else {
        json!({"type":"directory"})
    };
    util::write_json(
        &receipt,
        &json!({"kind":"syft-grype-content-evidence","schema_version":1,"CreatedAt":Utc::now().to_rfc3339(),"cataloger_image":sbom::SYFT,"scanner_image":GRYPE,"Metadata":subject,"sbom":{"path":relative,"digest":util::hash(&saved)?},"report":{"path":format!("{name}.grype.json"),"digest":util::hash(&report)?},"findings":findings.len(),"authorization":"none; trusted unsigned content evidence only"}),
    )?;
    println!(
        "{} {name}: {} Grype matches",
        if findings.is_empty() { "PASS" } else { "FAIL" },
        findings.len()
    );
    Ok(findings.len())
}
pub fn receipt(path: &Path, now: DateTime<Utc>) -> Result<Value> {
    let value = util::json(path)?;
    ensure(
        value["kind"] == "syft-grype-content-evidence"
            && value["schema_version"] == 1
            && value["cataloger_image"] == sbom::SYFT
            && value["scanner_image"] == GRYPE,
        "Unsupported content receipt",
    )?;
    crate::evidence::fresh(
        value["CreatedAt"].as_str().ok_or("Missing evidence time")?,
        now,
    )?;
    let parent = path.parent().ok_or("Missing evidence parent")?;
    let load = |key: &str| -> Result<Value> {
        let name = value[key]["path"]
            .as_str()
            .ok_or("Missing bound artifact")?;
        ensure(
            Path::new(name).components().count() == 1
                && Path::new(name).file_name().is_some()
                && !name.starts_with('.'),
            "Escaping evidence artifact",
        )?;
        let file = parent.join(name);
        ensure(
            util::hash(&file)? == value[key]["digest"],
            "Substituted SBOM/report",
        )?;
        util::json(&file)
    };
    let catalog = load("sbom")?;
    let raw = load("report")?;
    let findings = validate_report(&catalog, &raw, now)?;
    let subject = if catalog["source"]["type"] == "image" {
        image_subject(&catalog)?
    } else {
        json!({"type":"directory"})
    };
    ensure(
        value["Metadata"] == subject && value["findings"] == findings.len(),
        "Changed receipt subject/count",
    )?;
    // Keep the existing low-level config/layer verifier scanner-independent.
    Ok(
        json!({"CreatedAt":value["CreatedAt"],"Metadata":subject,"Results":[{"Vulnerabilities":findings}],"raw_matches":findings}),
    )
}
pub fn transition(policy: &Value) -> Result {
    ensure(
        policy["schema_version"] == 1
            && policy["baseline_scanner"] == "trivy"
            && policy["candidate_cataloger"] == "syft:1.55.0"
            && policy["candidate_scanner"] == "grype:0.121.0",
        "Unknown scanner transition",
    )?;
    ensure(
        policy["state"] == "verified" && policy["unresolved_baseline_asset_advisory_pairs"] == 0,
        "Baseline-only scanner findings require reconciliation",
    )?;
    ensure(
        policy["closure_evidence_sha256"]
            .as_array()
            .is_some_and(|v| {
                !v.is_empty()
                    && v.iter().all(|v| {
                        v.as_str().is_some_and(|s| {
                            s.len() == 64
                                && s.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                    })
            }),
        "Missing independently reviewed transition evidence",
    )
}
pub fn scan_generated(root: &Path, directory: &Path) -> Result {
    util::local_docker(root)?;
    let directory = directory.canonicalize()?;
    let cache = root.join(".work/grype-cache");
    database(root, &cache, &directory)?;
    let materials = util::json(&directory.join("materials.json"))?;
    if let Ok(revision) = std::env::var("GITHUB_SHA") {
        ensure(
            materials["source_revision"] == revision && materials["working_tree_dirty"] == false,
            "CI requires same-revision clean SBOM materials",
        )?;
    }
    ensure(
        materials["generator_image"] == sbom::SYFT,
        "Unexpected catalog generator",
    )?;
    let mut count = 0;
    for name in ["source", "runtime", "builder"] {
        let path = format!("{name}.syft.json");
        let input = directory.join(&path);
        let entry = materials["artifacts"]
            .as_array()
            .ok_or("Missing bound material")?
            .iter()
            .find(|v| v["path"] == path)
            .ok_or("Unbound SBOM")?;
        ensure(
            entry["digest"] == util::hash(&input)?,
            "SBOM/material substitution",
        )?;
        if name != "source" {
            let subject = image_subject(&util::json(&input)?)?;
            ensure(
                subject["ImageID"] == materials["images"][name]["config_digest"]
                    && subject["DiffIDs"] == materials["images"][name]["layers"],
                "SBOM/image material mismatch",
            )?;
        }
        count += scan(root, &input, &directory, &cache, name)?;
    }
    ensure(count == 0, "Grype findings remain blocking")
}
