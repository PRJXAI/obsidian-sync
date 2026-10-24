//! Default declared-image gate: Syft -> immutable native SBOM -> offline Grype.
use crate::{Result, ensure, grype, sbom, security, util};
use chrono::Utc;
use serde_json::{Value, json};
use std::{fs, path::Path};

pub fn output(root: &Path, platform: &str) -> Result<std::path::PathBuf> {
    ensure(
        ["linux/amd64", "linux/arm64"].contains(&platform),
        "Unsupported platform",
    )?;
    Ok(root.join(".work/security/sbom-chain").join(
        platform
            .split('/')
            .next_back()
            .ok_or("Missing architecture")?,
    ))
}
pub fn scan(root: &Path, platform: &str) -> Result {
    util::local_docker(root)?;
    let output = output(root, platform)?;
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let summary_path = output.join("summary.json");
    if summary_path.exists() {
        fs::remove_file(&summary_path)?;
    }
    let cache = root.join(".work/grype-cache");
    grype::database(root, &cache, &output)?;
    let mut entries = Vec::new();
    for (index, (image, sources)) in security::inventory(root)?.iter().enumerate() {
        let name = format!("image-{index:02}");
        let receipt = output.join(format!("{name}.scan.json"));
        // Never reuse a previous receipt after a failed generation/scan.
        if receipt.symlink_metadata().is_ok() {
            fs::remove_file(&receipt)?;
        }
        let result = sbom::catalog_registry(root, image, platform, &output, &name).and_then(|()| {
            grype::scan(
                root,
                &output.join(format!("{name}.syft.json")),
                &output,
                &cache,
                &name,
            )
        });
        let (status, count) = match result {
            Ok(n) => (if n == 0 { "pass" } else { "findings" }, Some(n)),
            Err(_) => ("error", None),
        };
        entries.push(json!({"image":image,"sources":sources,"status":status,"findings":count,"receipt":format!("{name}.scan.json")}));
        println!(
            "{} image index {index}",
            if status == "pass" { "PASS" } else { "FAIL" }
        );
    }
    util::write_json(
        &summary_path,
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"platform":platform,"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"images":entries}),
    )?;
    ensure(
        entries.iter().all(|v| v["status"] == "pass"),
        "SBOM vulnerability findings/errors remain blocking",
    )
}
pub fn ledger(root: &Path, platform: &str, revision: &str) -> Result {
    ensure(
        crate::policy::is_revision(revision),
        "Invalid source revision",
    )?;
    let output = output(root, platform)?;
    let destination = output.join("findings-ledger.json");
    if destination.exists() {
        fs::remove_file(&destination)?;
    }
    let summary = util::json(&output.join("summary.json"))?;
    ensure(
        summary["cataloger_image"] == sbom::SYFT
            && summary["scanner_image"] == grype::GRYPE
            && summary["platform"] == platform,
        "Unexpected evidence tools/platform",
    )?;
    crate::evidence::fresh(
        summary["created_at"].as_str().ok_or("Missing scan time")?,
        Utc::now(),
    )?;
    let inventory = security::inventory(root)?;
    let entries = summary["images"]
        .as_array()
        .ok_or("Missing image inventory")?;
    ensure(
        inventory.len() == entries.len(),
        "Incomplete scan inventory",
    )?;
    let mut records = Vec::new();
    for (index, ((image, _), entry)) in inventory.iter().zip(entries).enumerate() {
        let name = format!("image-{index:02}.scan.json");
        ensure(
            entry["image"] == *image && entry["receipt"] == name && entry["status"] != "error",
            "Substituted/incomplete scan",
        )?;
        let evidence = grype::receipt(&output.join(name), Utc::now())?;
        let findings=evidence["raw_matches"].as_array().ok_or("Missing matches")?.iter().map(|v| {
            let key=json!([platform,image,evidence["Metadata"]["ImageID"],v["artifact"]["id"],v["vulnerability"]["id"]]);
            json!({"id":util::digest(key.to_string().as_bytes()),"advisory":v["vulnerability"]["id"],"severity":v["vulnerability"]["severity"],"package":v["artifact"]["name"],"installed_version":v["artifact"]["version"],"locations":v["artifact"]["locations"],"fix":v["vulnerability"]["fix"],"status":"under_investigation","owner":null,"applicability_evidence":null})
        }).collect::<Vec<_>>();
        records.push(json!({"image":image,"subject":evidence["Metadata"],"findings":findings}));
    }
    util::write_json(
        &destination,
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"source_revision":revision,"platform":platform,"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"images":records,"native_review":"pending","baseline_trivy_findings":"remain open pending explicit reconciliation; scanner change is not closure","authorization":"none"}),
    )
}
pub fn public_summary(root: &Path, revision: &str) -> Result {
    ensure(crate::policy::is_revision(revision), "Invalid revision")?;
    let output = root.join(".work/public-security");
    ensure(!output.exists(), "Refusing stale publication directory")?;
    fs::create_dir_all(&output)?;
    let mut results = serde_json::Map::new();
    for name in ["source", "runtime", "builder"] {
        let result = match grype::receipt(
            &root.join(format!(".work/sbom/{name}.scan.json")),
            Utc::now(),
        ) {
            Ok(v) => {
                let n = v["raw_matches"]
                    .as_array()
                    .map(Vec::len)
                    .ok_or("Missing finding count")?;
                json!({"status":if n==0 {"pass"} else {"fail"},"findings":n})
            }
            Err(_) => json!({"status":"error"}),
        };
        results.insert(name.into(), result);
    }
    for name in ["gitleaks.json", "gitleaks-history.json"] {
        let result = match util::json(&root.join(".work/security").join(name)).and_then(|v| {
            v.as_array()
                .map(Vec::len)
                .ok_or_else(|| "Invalid secret report".into())
        }) {
            Ok(n) => json!({"status":if n==0 {"pass"} else {"fail"},"findings":n}),
            Err(_) => json!({"status":"error"}),
        };
        results.insert(name.into(), result);
    }
    let inventory = security::inventory(root)?;
    let status = match util::json(&output_for_summary(root)?) {
        Ok(v) => {
            let entries = v["images"].as_array();
            let complete = entries.is_some_and(|v| v.len() == inventory.len());
            let errors = entries
                .map(|v| v.iter().filter(|v| v["status"] == "error").count())
                .unwrap_or(inventory.len());
            let failed = entries
                .map(|v| v.iter().filter(|v| v["status"] != "pass").count())
                .unwrap_or(inventory.len());
            json!({"status":if !complete || errors>0 {"error"} else if failed>0 {"fail"} else {"pass"},"images":inventory.len(),"failed_images":failed,"scan_errors":errors})
        }
        Err(_) => json!({"status":"error"}),
    };
    results.insert("supply_chain".into(), status);
    util::write_json(
        &output.join("summary.json"),
        &json!({"schema_version":2,"source_revision":revision,"results":Value::Object(results),"raw_reports_published":false,"raw_evidence_archive":"owner_approved_private_destination_pending"}),
    )
}
pub fn compare_baseline(root: &Path, platform: &str) -> Result {
    let directory = output(root, platform)?;
    let current = util::json(&directory.join("summary.json"))?;
    let old_directory = root
        .join(".work/security/supply-chain")
        .join(platform.split('/').next_back().ok_or("Invalid platform")?);
    let old = util::json(&old_directory.join("summary.json"))?;
    ensure(
        old["scanner"] == security::TRIVY && old["platform"] == platform,
        "Untrusted comparison baseline",
    )?;
    let mut records = Vec::new();
    let mut unresolved = 0;
    for entry in old["images"]
        .as_array()
        .ok_or("Missing baseline inventory")?
    {
        let image = entry["image"].as_str().ok_or("Missing image")?;
        let index = current["images"]
            .as_array()
            .ok_or("Missing current inventory")?
            .iter()
            .position(|v| v["image"] == image)
            .ok_or("Baseline asset omitted")?;
        let baseline_file = entry["report"].as_str().ok_or("Missing baseline file")?;
        ensure(
            std::path::Path::new(baseline_file).components().count() == 1
                && !baseline_file.starts_with('.'),
            "Escaping baseline report",
        )?;
        let baseline = util::json(&old_directory.join(baseline_file))?;
        let evidence = grype::receipt(
            &directory.join(format!("image-{index:02}.scan.json")),
            Utc::now(),
        )?;
        ensure(
            baseline["Metadata"]["ImageID"] == evidence["Metadata"]["ImageID"],
            "Compared different binary/platform configurations",
        )?;
        let before = crate::evidence::findings(&baseline, Some(image), Utc::now())?
            .iter()
            .filter_map(|v| v["VulnerabilityID"].as_str().map(String::from))
            .collect::<std::collections::BTreeSet<_>>();
        let mut after = std::collections::BTreeSet::new();
        for value in evidence["raw_matches"]
            .as_array()
            .ok_or("Missing Grype matches")?
        {
            if let Some(id) = value["vulnerability"]["id"].as_str() {
                after.insert(id.to_string());
            }
            if let Some(related) = value["relatedVulnerabilities"].as_array() {
                for v in related {
                    if let Some(id) = v["id"].as_str() {
                        after.insert(id.to_string());
                    }
                }
            }
        }
        let missing = before.difference(&after).cloned().collect::<Vec<_>>();
        unresolved += missing.len();
        records.push(json!({"image":image,"config_digest":evidence["Metadata"]["ImageID"],"baseline_advisories":before.len(),"grype_advisories_including_aliases":after.len(),"baseline_only_under_investigation":missing}));
    }
    util::write_json(
        &directory.join("scanner-comparison.json"),
        &json!({"images":records,"unresolved_baseline_only_advisories":unresolved,"disposition":"under_investigation; changing scanners does not close findings"}),
    )?;
    ensure(
        unresolved == 0,
        "Scanner applicability/coverage differences require review",
    )
}
fn output_for_summary(root: &Path) -> Result<std::path::PathBuf> {
    Ok(output(root, "linux/amd64")?.join("summary.json"))
}
