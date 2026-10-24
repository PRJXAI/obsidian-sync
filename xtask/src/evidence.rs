use crate::{Result, ensure, images};
use chrono::{DateTime, Utc};
use serde_json::Value;

pub const SEVERITIES: [&str; 5] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
pub fn fresh(value: &str, now: DateTime<Utc>) -> Result {
    let timestamp = DateTime::parse_from_rfc3339(value)?;
    let age = now.signed_duration_since(timestamp).num_seconds();
    ensure((-300..=86400).contains(&age), "Stale/future evidence")
}
pub fn findings(
    report: &Value,
    expected_image: Option<&str>,
    now: DateTime<Utc>,
) -> Result<Vec<Value>> {
    ensure(report["SchemaVersion"] == 2, "Unsupported scan schema")?;
    fresh(
        report["CreatedAt"].as_str().ok_or("Missing scan time")?,
        now,
    )?;
    ensure(
        report["Metadata"]["ImageID"]
            .as_str()
            .is_some_and(images::is_digest),
        "Missing immutable scan identity",
    )?;
    if let Some(image) = expected_image {
        ensure(report["ArtifactName"] == image, "Scan substitution")?;
    }
    let results = report["Results"].as_array().ok_or("Missing results")?;
    ensure(!results.is_empty(), "Empty results")?;
    let mut findings = Vec::new();
    for result in results {
        ensure(result.is_object(), "Invalid result")?;
        if let Some(values) = result.get("Vulnerabilities") {
            for value in values.as_array().ok_or("Invalid findings")? {
                ensure(
                    value["VulnerabilityID"].is_string()
                        && value["Severity"]
                            .as_str()
                            .is_some_and(|s| SEVERITIES.contains(&s)),
                    "Unknown finding schema",
                )?;
                let mut finding = value.clone();
                finding["_scan_target"] = result["Target"].clone();
                findings.push(finding);
            }
        }
    }
    Ok(findings)
}
