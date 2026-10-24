#![forbid(unsafe_code)]
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use std::fs;
use xtask::{Result, grype, util};

fn fixture() -> (Value, Value) {
    let config=json!({"rootfs":{"diff_ids":[format!("sha256:{}","b".repeat(64))]},"config":{"User":"65532:65532","Entrypoint":["/server"]},"architecture":"arm64","os":"linux"}).to_string();
    let metadata = json!({"imageID":format!("sha256:{}",util::digest(config.as_bytes())),"config":base64::engine::general_purpose::STANDARD.encode(config)});
    let catalog = json!({"schema":{"version":"16.1.11"},"descriptor":{"name":"syft","version":"1.55.0"},"artifacts":[{"id":"pkg","name":"fixture","version":"1","type":"apk"}],"source":{"type":"image","metadata":metadata}});
    let report = json!({"matches":[],"source":{"type":"image","target":metadata},"descriptor":{"name":"grype","version":"0.121.0","timestamp":Utc::now().to_rfc3339(),"configuration":{"include-matcher-suppressions":true},"db":{"status":{"valid":true,"schemaVersion":"v6.1.10","built":Utc::now().to_rfc3339()}}}});
    (catalog, report)
}
fn finding(severity: &str) -> Value {
    json!({"artifact":{"id":"pkg","name":"fixture","version":"1"},"vulnerability":{"id":"CVE-fixture","severity":severity}})
}
#[test]
fn scanner_transition_cannot_drop_unreconciled_baseline_findings() -> Result {
    let mut policy = json!({"schema_version":1,"baseline_scanner":"trivy","candidate_cataloger":"syft:1.55.0","candidate_scanner":"grype:0.121.0","state":"under_investigation","unresolved_baseline_asset_advisory_pairs":27,"closure_evidence_sha256":[]});
    assert!(grype::transition(&policy).is_err());
    policy["state"] = json!("verified");
    assert!(grype::transition(&policy).is_err());
    policy["unresolved_baseline_asset_advisory_pairs"] = json!(0);
    assert!(grype::transition(&policy).is_err());
    policy["closure_evidence_sha256"] = json!(["a".repeat(64)]);
    grype::transition(&policy)
}
#[test]
fn valid_clean_report_and_image_subject() -> Result {
    let (catalog, report) = fixture();
    assert!(grype::validate_report(&catalog, &report, Utc::now())?.is_empty());
    let subject = grype::image_subject(&catalog)?;
    assert_eq!(subject["architecture"], "arm64");
    assert!(subject["DiffIDs"].as_array().is_some_and(|v| v.len() == 1));
    Ok(())
}
#[test]
fn every_severity_and_suppressed_match_remains_a_finding() -> Result {
    let (catalog, mut report) = fixture();
    for severity in grype::SEVERITIES {
        report["matches"] = json!([finding(severity)]);
        assert_eq!(
            grype::validate_report(&catalog, &report, Utc::now())?.len(),
            1
        );
    }
    report["matches"] = json!([]);
    report["ignoredMatches"] = json!([finding("Unknown")]);
    report["descriptor"]["configuration"]["ignore"] = json!([{"reason":"vendor default"}]);
    assert_eq!(
        grype::validate_report(&catalog, &report, Utc::now())?.len(),
        1
    );
    Ok(())
}
#[test]
fn incomplete_stale_future_wrong_source_and_unknown_schema_fail_closed() {
    for kind in [
        "matches",
        "suppression",
        "scanner",
        "db",
        "db-age",
        "db-future",
        "time",
        "future",
        "source",
        "foreign",
        "severity",
    ] {
        let (catalog, mut report) = fixture();
        match kind {
            "matches" => {
                report.as_object_mut().unwrap().remove("matches");
            }
            "suppression" => {
                report["descriptor"]["configuration"]["include-matcher-suppressions"] = json!(false)
            }
            "scanner" => report["descriptor"]["version"] = json!("unknown"),
            "db" => report["descriptor"]["db"]["status"]["valid"] = json!(false),
            "db-age" => {
                report["descriptor"]["db"]["status"]["built"] =
                    json!((Utc::now() - Duration::days(4)).to_rfc3339())
            }
            "db-future" => {
                report["descriptor"]["db"]["status"]["built"] =
                    json!((Utc::now() + Duration::days(1)).to_rfc3339())
            }
            "time" | "future" => {
                report["descriptor"]["timestamp"] = json!(
                    (Utc::now() + Duration::days(if kind == "future" { 1 } else { -2 }))
                        .to_rfc3339()
                )
            }
            "source" => report["source"]["target"] = json!("other"),
            "foreign" => {
                report["matches"] = json!([finding("Low")]);
                report["matches"][0]["artifact"]["id"] = json!("other");
            }
            "severity" => report["matches"] = json!([finding("UNRECOGNIZED")]),
            _ => unreachable!(),
        }
        assert!(
            grype::validate_report(&catalog, &report, Utc::now()).is_err(),
            "{kind}"
        );
    }
}
#[test]
fn vacuous_duplicate_and_changed_image_catalogs_fail() -> Result {
    let (catalog, _) = fixture();
    for kind in ["empty", "duplicate", "config", "schema"] {
        let mut value = catalog.clone();
        match kind {
            "empty" => value["artifacts"] = json!([]),
            "duplicate" => {
                value["artifacts"] = json!([value["artifacts"][0], value["artifacts"][0]])
            }
            "config" => {
                value["source"]["metadata"]["imageID"] = json!(format!("sha256:{}", "c".repeat(64)))
            }
            "schema" => value["schema"]["version"] = json!("unknown"),
            _ => unreachable!(),
        }
        assert!(grype::image_subject(&value).is_err(), "{kind}");
    }
    Ok(())
}
#[test]
fn receipt_binds_exact_sbom_report_subject_count_and_time() -> Result {
    let temp = tempfile::tempdir()?;
    let root = temp.path();
    let (catalog, report) = fixture();
    util::write_json(&root.join("runtime.syft.json"), &catalog)?;
    util::write_json(&root.join("runtime.grype.json"), &report)?;
    let value = json!({"kind":"syft-grype-content-evidence","schema_version":1,"CreatedAt":Utc::now().to_rfc3339(),"cataloger_image":xtask::sbom::SYFT,"scanner_image":grype::GRYPE,"Metadata":grype::image_subject(&catalog)?,"findings":0,"sbom":{"path":"runtime.syft.json","digest":util::hash(&root.join("runtime.syft.json"))?},"report":{"path":"runtime.grype.json","digest":util::hash(&root.join("runtime.grype.json"))?}});
    let receipt = root.join("runtime.scan.json");
    util::write_json(&receipt, &value)?;
    grype::receipt(&receipt, Utc::now())?;
    for kind in ["sbom", "report", "subject", "count", "time", "escape"] {
        let mut bad = value.clone();
        match kind {
            "sbom" => bad["sbom"]["digest"] = json!(format!("sha256:{}", "d".repeat(64))),
            "report" => bad["report"]["digest"] = json!(format!("sha256:{}", "d".repeat(64))),
            "subject" => bad["Metadata"]["ImageID"] = json!("other"),
            "count" => bad["findings"] = json!(1),
            "time" => bad["CreatedAt"] = json!((Utc::now() - Duration::days(2)).to_rfc3339()),
            "escape" => bad["report"]["path"] = json!("../outside.json"),
            _ => unreachable!(),
        }
        util::write_json(&receipt, &bad)?;
        assert!(grype::receipt(&receipt, Utc::now()).is_err(), "{kind}");
    }
    fs::write(root.join("runtime.grype.json"), "{}")?;
    util::write_json(&receipt, &value)?;
    assert!(grype::receipt(&receipt, Utc::now()).is_err());
    Ok(())
}
