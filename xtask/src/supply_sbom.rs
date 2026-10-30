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
        let result = result
            .and_then(|n| grype::receipt(&receipt, Utc::now()).map(|v| (n, v["risk"].clone())));
        let (status, count, risk) = match result {
            Ok((n, risk)) => (
                if risk["blocking"] != 0 {
                    "findings"
                } else if n == 0 {
                    "pass"
                } else {
                    "accepted-risk"
                },
                Some(n),
                risk,
            ),
            Err(_) => ("error", None, Value::Null),
        };
        entries.push(json!({"image":image,"sources":sources,"status":status,"findings":count,"risk":risk,"receipt":format!("{name}.scan.json")}));
        println!(
            "{} image index {index}",
            if status == "pass" || status == "accepted-risk" {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }
    util::write_json(
        &summary_path,
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"platform":platform,"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"images":entries}),
    )?;
    ensure(
        entries
            .iter()
            .all(|v| v["status"] == "pass" || v["status"] == "accepted-risk"),
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
        let matches = evidence["raw_matches"]
            .as_array()
            .ok_or("Missing matches")?;
        ensure(
            entry["findings"] == matches.len()
                && entry["status"]
                    == if matches.is_empty() {
                        "pass"
                    } else if evidence["risk"]["blocking"] == 0 {
                        "accepted-risk"
                    } else {
                        "findings"
                    },
            "Contradictory scan summary",
        )?;
        let findings=matches.iter().map(|v| {
            let key=json!([platform,image,evidence["Metadata"]["ImageID"],v["artifact"]["id"],v["vulnerability"]["id"]]);
            json!({"id":util::digest(key.to_string().as_bytes()),"advisory":v["vulnerability"]["id"],"severity":v["vulnerability"]["severity"],"package":v["artifact"]["name"],"installed_version":v["artifact"]["version"],"locations":v["artifact"]["locations"],"fix":v["vulnerability"]["fix"],"status":if evidence["risk"]["blocking"] == 0 {"accepted-risk"} else {"under_investigation"},"owner":null,"applicability_evidence":null})
        }).collect::<Vec<_>>();
        records.push(json!({"image":image,"subject":evidence["Metadata"],"findings":findings,"risk":evidence["risk"]}));
    }
    util::write_json(
        &destination,
        &json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"source_revision":revision,"platform":platform,"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"images":records,"native_review":"pending","authorization":"none"}),
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
                json!({"status":if v["risk"]["blocking"] != 0 {"fail"} else if n==0 {"pass"} else {"accepted-risk"},"findings":n,"accepted":v["risk"]["accepted"],"blocking":v["risk"]["blocking"]})
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
                .map(|v| {
                    v.iter()
                        .filter(|v| v["status"] != "pass" && v["status"] != "accepted-risk")
                        .count()
                })
                .unwrap_or(inventory.len());
            let accepted = entries
                .map(|v| v.iter().filter(|v| v["status"] == "accepted-risk").count())
                .unwrap_or(0);
            json!({"status":if !complete || errors>0 {"error"} else if failed>0 {"fail"} else if accepted>0 {"accepted-risk"} else {"pass"},"images":inventory.len(),"failed_images":failed,"accepted_risk_images":accepted,"scan_errors":errors})
        }
        Err(_) => json!({"status":"error"}),
    };
    results.insert("supply_chain".into(), status);
    util::write_json(
        &output.join("summary.json"),
        &json!({"schema_version":2,"source_revision":revision,"results":Value::Object(results),"raw_reports_published":false,"raw_evidence_archive":"owner_approved_private_destination_pending"}),
    )
}
fn output_for_summary(root: &Path) -> Result<std::path::PathBuf> {
    Ok(output(root, "linux/amd64")?.join("summary.json"))
}
