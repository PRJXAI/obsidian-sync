use base64::Engine;
use chrono::Utc;
use serde_json::{Value, json};
use std::{fs, path::Path};
use xtask::{Result, grype, sbom, util};

pub fn fixture() -> (Value, Value) {
    let config=json!({"rootfs":{"diff_ids":[format!("sha256:{}","b".repeat(64))]},"config":{"User":"65532:65532","Entrypoint":["/server"]},"architecture":"arm64","os":"linux"}).to_string();
    let metadata = json!({"imageID":format!("sha256:{}",util::digest(config.as_bytes())),"config":base64::engine::general_purpose::STANDARD.encode(config)});
    let catalog = json!({"schema":{"version":"16.1.11"},"descriptor":{"name":"syft","version":"1.55.0"},"artifacts":[{"id":"pkg","name":"fixture","version":"1","type":"apk"}],"source":{"type":"image","metadata":metadata}});
    let report = json!({"matches":[],"source":{"type":"image","target":metadata},"descriptor":{"name":"grype","version":"0.121.0","timestamp":Utc::now().to_rfc3339(),"configuration":{"include-matcher-suppressions":true},"db":{"status":{"valid":true,"schemaVersion":"v6.1.10","built":Utc::now().to_rfc3339()}}}});
    (catalog, report)
}
pub fn finding(severity: &str) -> Value {
    json!({"artifact":{"id":"pkg","name":"fixture","version":"1"},"vulnerability":{"id":"CVE-fixture","severity":severity}})
}
pub fn write_receipt(root: &Path, name: &str, catalog: &Value, report: &Value) -> Result<Value> {
    fs::create_dir_all(root)?;
    let sbom = format!("{name}.syft.json");
    let raw = format!("{name}.grype.json");
    util::write_json(&root.join(&sbom), catalog)?;
    util::write_json(&root.join(&raw), report)?;
    let count = report["matches"].as_array().map_or(0, Vec::len)
        + report["ignoredMatches"].as_array().map_or(0, Vec::len);
    let receipt = json!({"kind":"syft-grype-content-evidence","schema_version":1,"CreatedAt":Utc::now().to_rfc3339(),"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,"Metadata":grype::image_subject(catalog)?,"findings":count,"sbom":{"path":sbom,"digest":util::hash(&root.join(&sbom))?},"report":{"path":raw,"digest":util::hash(&root.join(&raw))?}});
    util::write_json(&root.join(format!("{name}.scan.json")), &receipt)?;
    Ok(receipt)
}
