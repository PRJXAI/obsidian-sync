#![forbid(unsafe_code)]
mod support;
use chrono::{Duration, Utc};
use serde_json::json;
use std::fs;
use support::{finding, fixture};
use xtask::{Result, grype, util};

#[test]
fn retired_scanner_commands_and_gate_are_not_exposed() -> Result {
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("--help")
        .output()?;
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout)?;
    for command in [
        "compare-trivy",
        "compare-trivy-supply-chain",
        "compare-scanner-baseline",
        "check-scanner-transition",
    ] {
        assert!(!help.contains(command));
        assert!(
            !std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
                .arg(command)
                .output()?
                .status
                .success()
        );
    }
    for command in [
        "scan-sbom",
        "scan-supply-chain",
        "verify-release",
        "findings-ledger",
    ] {
        assert!(help.contains(command));
    }
    let workflow = fs::read_to_string(xtask::root().join(".github/workflows/ci.yml"))?;
    assert!(!workflow.contains("check-scanner-transition") && !workflow.contains("trivy"));
    assert!(!workflow.contains("continue-on-error"));
    assert!(workflow.contains("needs: [rust, build, security, integration, sbom]"));
    assert!(
        !xtask::root()
            .join(".github/scanner-transition.json")
            .exists()
    );
    Ok(())
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
    let value = support::write_receipt(root, "runtime", &catalog, &report)?;
    let receipt = root.join("runtime.scan.json");
    util::write_json(&receipt, &value)?;
    grype::receipt(&receipt, Utc::now())?;
    for kind in [
        "sbom",
        "report",
        "subject",
        "count",
        "time",
        "escape",
        "scope",
        "scope-type",
        "risk",
    ] {
        let mut bad = value.clone();
        match kind {
            "sbom" => bad["sbom"]["digest"] = json!(format!("sha256:{}", "d".repeat(64))),
            "report" => bad["report"]["digest"] = json!(format!("sha256:{}", "d".repeat(64))),
            "subject" => bad["Metadata"]["ImageID"] = json!("other"),
            "count" => bad["findings"] = json!(1),
            "time" => bad["CreatedAt"] = json!((Utc::now() - Duration::days(2)).to_rfc3339()),
            "escape" => bad["report"]["path"] = json!("../outside.json"),
            "scope" => bad["scope"] = json!("builder"),
            "scope-type" => bad["scope"] = json!([]),
            "risk" => bad["risk"] = json!({"accepted":99,"blocking":0}),
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
