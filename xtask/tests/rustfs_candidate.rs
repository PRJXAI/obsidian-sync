//! Fixed released supplier evaluation, never an override for the declared-image gate.
use std::fs;
use xtask::{Result, ensure, grype, sbom, util};

const CANDIDATE: &str =
    "rustfs/rustfs:1.0.4@sha256:ed9210d6411d77ffceb70d94b964a3cb7d225983368bc25bebe01e995293dcc2";

#[test]
#[ignore = "retrieves the fixed public RustFS release and fresh advisory data; no adoption"]
fn released_rustfs_candidate_has_zero_findings_on_both_architectures() -> Result {
    let root = xtask::root();
    util::install_cancellation()?;
    util::local_docker(&root)?;
    let output = root.join(".work/security/rustfs-1.0.4-evaluation");
    ensure(!output.exists(), "Refusing stale candidate evaluation")?;
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let cache = root.join(".work/grype-cache");
    grype::database(&root, &cache, &output)?;
    let mut entries = Vec::new();
    for arch in ["amd64", "arm64"] {
        let directory = output.join(arch);
        fs::create_dir(&directory)?;
        let platform = format!("linux/{arch}");
        let findings = sbom::catalog_registry(&root, CANDIDATE, &platform, &directory, "candidate")
            .and_then(|()| {
                grype::scan(
                    &root,
                    &directory.join("candidate.syft.json"),
                    &directory,
                    &cache,
                    "candidate",
                )
            });
        entries.push(match findings {
            Ok(n) => serde_json::json!({"platform":platform,"findings":n,"status":if n==0 {"pass"} else {"findings"}}),
            Err(_) => serde_json::json!({"platform":platform,"status":"error"}),
        });
    }
    util::write_json(
        &output.join("summary.json"),
        &serde_json::json!({
            "candidate":CANDIDATE,
            "created_at":chrono::Utc::now().to_rfc3339(),
            "cataloger_image":sbom::SYFT,
            "scanner_image":grype::GRYPE,
            "platforms":entries,
            "native_runtime_validation":false,
            "adoption_authorized":false
        }),
    )?;
    ensure(
        entries.iter().all(|v| v["status"] == "pass"),
        "Candidate findings/errors remain blocking",
    )
}
