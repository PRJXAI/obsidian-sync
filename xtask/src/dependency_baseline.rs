//! Private, read-only aggregation of already bound evidence, never a scan or approval.
use crate::{Result, ensure, grype, images, sbom, security, supply_sbom, util};
use chrono::Utc;
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::Write, os::unix::fs::PermissionsExt, path::Path};

// Cap aggregate memory accounting and publication before writes, not after an
// oversized pretty serialization has already allocated/written its bytes.
struct Bounded<W> {
    inner: W,
    remaining: usize,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("Dependency baseline byte limit"));
        }
        let written = self.inner.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}
fn append(assets: &mut Vec<Value>, record: Value, budget: &mut usize) -> Result {
    let mut counter = Bounded {
        inner: std::io::sink(),
        remaining: *budget,
    };
    serde_json::to_writer(&mut counter, &record)?;
    *budget = counter.remaining;
    assets.push(record);
    Ok(())
}
fn save(directory: &Path, destination: &Path, value: &Value, limit: usize) -> Result {
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer_pretty(
        &mut Bounded {
            inner: temporary.as_file_mut(),
            remaining: limit,
        },
        value,
    )?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist_noclobber(destination)?;
    Ok(())
}

fn asset(directory: &Path, name: &str, label: &str) -> Result<Value> {
    let path = directory.join(format!("{name}.scan.json"));
    let validated = grype::receipt(&path, Utc::now())?;
    let receipt = util::json(&path)?;
    let report =
        util::json(&directory.join(receipt["report"]["path"].as_str().ok_or("Missing report")?))?;
    let matches = validated["raw_matches"]
        .as_array()
        .ok_or("Missing findings")?;
    let normal = report["matches"]
        .as_array()
        .ok_or("Missing normal matches")?
        .len();
    let suppressed = report.get("ignoredMatches").map_or(Ok(0), |v| {
        v.as_array()
            .map(Vec::len)
            .ok_or("Invalid suppressed matches")
    })?;
    ensure(
        normal + suppressed == matches.len(),
        "Incomplete match accounting",
    )?;
    let mut groups = BTreeMap::<String, Value>::new();
    let mut counts = BTreeMap::<String, usize>::new();
    for severity in grype::SEVERITIES {
        counts.insert(severity.into(), 0);
    }
    for (index, finding) in matches.iter().enumerate() {
        let severity = finding["vulnerability"]["severity"]
            .as_str()
            .ok_or("Missing severity")?;
        *counts.get_mut(severity).ok_or("Unknown severity")? += 1;
        let key = json!([
            finding["artifact"]["name"],
            finding["artifact"]["version"],
            finding["artifact"]["type"],
            finding["vulnerability"]["id"],
            finding["vulnerability"]["namespace"],
            finding["vulnerability"]["severity"],
            finding["vulnerability"]["fix"]
        ]);
        let id = util::digest(key.to_string().as_bytes());
        let group = groups.entry(id.clone()).or_insert_with(||json!({
            "id":id,"package":finding["artifact"]["name"],"installed_version":finding["artifact"]["version"],"type":finding["artifact"]["type"],"advisory":finding["vulnerability"]["id"],"namespace":finding["vulnerability"]["namespace"],"severity":severity,"fix":finding["vulnerability"]["fix"],
            "classification":if finding["vulnerability"]["fix"]["versions"].as_array().is_some_and(|v| !v.is_empty()) {"published-fix-needs-review"} else {"no-published-fix-in-report-needs-review"},
            "count":0,"suppressed":0,"occurrences":[],"status":"under_investigation","owner":null,"applicability_evidence":null
        }));
        group["count"] = json!(group["count"].as_u64().ok_or("Invalid group count")? + 1);
        group["suppressed"] = json!(
            group["suppressed"]
                .as_u64()
                .ok_or("Invalid suppression count")?
                + u64::from(index >= normal)
        );
        group["occurrences"].as_array_mut().ok_or("Invalid occurrences")?.push(json!({"report_match_index":index,"artifact_id":finding["artifact"]["id"],"locations":finding["artifact"]["locations"],"suppressed":index >= normal}));
    }
    Ok(
        json!({"asset":label,"subject":validated["Metadata"],"created_at":validated["CreatedAt"],"receipt_digest":util::hash(&path)?,"sbom":receipt["sbom"],"report":receipt["report"],"db":report["descriptor"]["db"]["status"],"findings":matches.len(),"suppressed":suppressed,"counts":counts,"groups":groups.into_values().collect::<Vec<_>>(),"risk":validated["risk"],"native_inventory_review":"pending","authorization":"none"}),
    )
}
fn build_materials(root: &Path) -> Result<Value> {
    let directory = root.join(".work/sbom");
    let materials = util::json(&directory.join("materials.json"))?;
    ensure(
        materials["schema_version"] == 1
            && materials["generator_image"] == sbom::SYFT
            && materials["source_revision"]
                .as_str()
                .is_some_and(crate::policy::is_revision)
            && materials["source_tree_digest"]
                .as_str()
                .is_some_and(images::is_digest)
            && materials["working_tree_dirty"].is_boolean(),
        "Invalid source materials",
    )?;
    let expected = [
        "runtime.cdx.json",
        "runtime.spdx.json",
        "runtime.syft.json",
        "builder.cdx.json",
        "builder.spdx.json",
        "builder.syft.json",
        "source.cdx.json",
        "source.spdx.json",
        "source.syft.json",
        "native-toolchain.txt",
    ];
    let entries = materials["artifacts"]
        .as_array()
        .ok_or("Missing bound materials")?;
    ensure(entries.len() == expected.len(), "Incomplete materials")?;
    for name in expected {
        let found = entries
            .iter()
            .filter(|entry| entry["path"] == name)
            .collect::<Vec<_>>();
        ensure(
            found.len() == 1 && found[0]["digest"] == util::hash(&directory.join(name))?,
            "Changed/duplicate bound material",
        )?;
    }
    Ok(materials)
}
/// Preserve separate registry and populated-build platforms/source identities.
/// Caller revision labels are deliberately absent: historical bytes keep their
/// original materials revision/dirty state rather than being relabeled current.
pub fn generate(root: &Path, platform: &str) -> Result {
    let directory = root.join(".work/security");
    fs::create_dir_all(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    let destination = directory.join("dependency-baseline.json");
    ensure(
        destination
            .symlink_metadata()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "Refusing existing baseline",
    )?;
    let registry = supply_sbom::output(root, platform)?;
    let summary_path = registry.join("summary.json");
    let summary = util::json(&summary_path)?;
    ensure(
        summary["schema_version"] == 1
            && summary["platform"] == platform
            && summary["cataloger_image"] == sbom::SYFT
            && summary["scanner_image"] == grype::GRYPE,
        "Unexpected registry summary",
    )?;
    crate::evidence::fresh(
        summary["created_at"].as_str().ok_or("Missing scan time")?,
        Utc::now(),
    )?;
    let inventory = security::inventory(root)?;
    let entries = summary["images"]
        .as_array()
        .ok_or("Missing registry inventory")?;
    ensure(
        entries.len() == inventory.len(),
        "Incomplete registry inventory",
    )?;
    ensure(inventory.len() <= 61, "Dependency baseline asset limit")?;
    let mut assets = Vec::new();
    let mut budget = util::JSON_LIMIT as usize;
    for (index, ((image, _), entry)) in inventory.iter().zip(entries).enumerate() {
        let name = format!("image-{index:02}");
        ensure(
            entry["image"] == *image && entry["receipt"] == format!("{name}.scan.json"),
            "Substituted registry member",
        )?;
        let mut record = asset(&registry, &name, image)?;
        ensure(
            record["subject"]["os"] == "linux"
                && record["subject"]["architecture"]
                    == platform.split('/').next_back().ok_or("Invalid platform")?,
            "Wrong registry architecture",
        )?;
        ensure(
            entry["findings"] == record["findings"]
                && entry["status"]
                    == if record["findings"] == 0 {
                        "pass"
                    } else if record["risk"]["blocking"] == 0 {
                        "accepted-risk"
                    } else {
                        "findings"
                    },
            "Contradictory registry summary",
        )?;
        record["scope"] = json!("registry-image");
        append(&mut assets, record, &mut budget)?;
    }
    let materials = build_materials(root)?;
    for name in ["source", "runtime", "builder"] {
        let mut record = asset(&root.join(".work/sbom"), name, name)?;
        let native_sbom = format!("{name}.syft.json");
        let bound = materials["artifacts"]
            .as_array()
            .ok_or("Missing artifacts")?
            .iter()
            .find(|v| v["path"] == native_sbom)
            .ok_or("Missing SBOM material")?;
        ensure(
            record["sbom"]["path"] == native_sbom && record["sbom"]["digest"] == bound["digest"],
            "SBOM/receipt/material substitution",
        )?;
        if name == "source" {
            ensure(
                record["subject"]["type"] == "directory",
                "Source receipt is not a directory inventory",
            )?;
        } else {
            let image = &materials["images"][name];
            ensure(
                record["subject"]["ImageID"] == image["config_digest"]
                    && record["subject"]["DiffIDs"] == image["layers"]
                    && record["subject"]["os"] == image["os"]
                    && record["subject"]["architecture"] == image["architecture"]
                    && image["architecture"]
                        .as_str()
                        .is_some_and(|v| ["amd64", "arm64"].contains(&v)),
                "Build subject/platform substitution",
            )?;
            ensure(
                image["archive_digest"]
                    .as_str()
                    .is_some_and(images::is_digest)
                    && image["image_id"].as_str().is_some_and(images::is_digest),
                "Missing image/archive identity",
            )?;
            record["materials"] = image.clone();
            record["archive_bytes_reverified"] = json!(false);
        }
        record["scope"] = json!("generated-source-or-populated-image");
        append(&mut assets, record, &mut budget)?;
    }
    let result = json!({"schema_version":1,"created_at":Utc::now().to_rfc3339(),"registry_platform":platform,"registry_summary_digest":util::hash(&summary_path)?,"materials_digest":util::hash(&root.join(".work/sbom/materials.json"))?,"build_source":{"revision":materials["source_revision"],"tree_digest":materials["source_tree_digest"],"dirty":materials["working_tree_dirty"]},"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"assets":assets,"authorization":"none","limitations":["Aggregates existing fresh trusted unsigned reports; no new scan or native execution","Source/build revision is the original materials identity, not current HEAD","Original build archive hashes are retained assertions, not rehashed archive bytes","Catalog completeness, fix availability, applicability and maintenance ownership need review","Raw evidence private; no public summary or risk acceptance"]});
    save(&directory, &destination, &result, util::JSON_LIMIT as usize)?;
    println!(
        "Private dependency baseline generated; findings remain open and no release is authorized"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_budget_never_writes_overflow_or_drops_an_occurrence() {
        let mut writer = Bounded {
            inner: Vec::new(),
            remaining: 4,
        };
        writer.write_all(b"1234").unwrap();
        assert!(writer.write_all(b"5").is_err());
        assert_eq!(writer.inner, b"1234");
        let mut records = Vec::new();
        let mut budget = 4;
        append(&mut records, json!(null), &mut budget).unwrap();
        assert!(append(&mut records, json!(null), &mut budget).is_err());
        assert_eq!(records, vec![json!(null)]);
    }
    #[test]
    fn bounded_publication_is_create_only_and_removes_partial_output() -> Result {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("baseline.json");
        assert!(save(temp.path(), &path, &json!("overflow"), 4).is_err());
        assert!(!path.exists());
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
        save(temp.path(), &path, &json!(null), 4)?;
        assert!(save(temp.path(), &path, &json!(true), 4).is_err());
        assert_eq!(fs::read(&path)?, b"null");
        Ok(())
    }
}
