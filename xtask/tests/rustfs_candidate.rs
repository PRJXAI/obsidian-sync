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

// This supplier asset describes Cargo.lock, not a verified per-platform binary graph.
fn review_supplier(
    bom: &serde_json::Value,
    provenance: &serde_json::Value,
) -> Result<serde_json::Value> {
    use serde_json::json;
    ensure(
        bom["bomFormat"] == "CycloneDX"
            && bom["specVersion"] == "1.6"
            && bom["metadata"]["component"]["name"] == "rustfs"
            && bom["metadata"]["component"]["version"] == "1.0.4",
        "Unexpected supplier inventory",
    )?;
    ensure(
        provenance["_type"] == "https://in-toto.io/Statement/v1"
            && provenance["predicateType"] == "https://slsa.dev/provenance/v1"
            && provenance["predicate"]["buildDefinition"]["internalParameters"]["sha"]
                == "46337942d55f3a8e6a97b147ca98d9ea8115555d",
        "Unexpected supplier source claim",
    )?;
    let components = bom["components"]
        .as_array()
        .ok_or("Missing supplier components")?;
    ensure(
        !components.is_empty()
            && components.iter().all(|v| {
                v["purl"]
                    .as_str()
                    .is_some_and(|s| s.starts_with("pkg:cargo/"))
            }),
        "Unexpected supplier component types",
    )?;
    ensure(
        bom["metadata"]["tools"]["components"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v["name"] == "Cargo.lock")),
        "Supplier generation scope changed",
    )?;
    let subjects = provenance["subject"]
        .as_array()
        .ok_or("Missing supplier subjects")?;
    for (name, digest) in [
        (
            "rustfs-linux-aarch64-musl-v1.0.4.zip",
            "81414fd0e41969f4f5c2e0555951cee76d3f224c112c269c80f52b31276f187a",
        ),
        (
            "rustfs-linux-x86_64-musl-v1.0.4.zip",
            "4924ad4b699b9f59943051efedae2d1eb6d4cac503a1b0384c4b25f7c2c31b5c",
        ),
    ] {
        let found = subjects
            .iter()
            .filter(|v| v["name"] == name)
            .collect::<Vec<_>>();
        ensure(
            found.len() == 1 && found[0]["digest"]["sha256"] == digest,
            "Ambiguous/changed supplier subject",
        )?;
    }
    Ok(
        json!({"source_revision":"46337942d55f3a8e6a97b147ca98d9ea8115555d","supplier_cargo_components":components.len(),"components_with_hashes":components.iter().filter(|v| v["hashes"].as_array().is_some_and(|a|!a.is_empty())).count(),"dependency_relationships":bom["dependencies"].as_array().map(Vec::len),"supplier_scope":"Cargo.lock inventory; not demonstrated binary/feature/native closure","archive_bytes_verified":false,"image_executable_binding_established":false,"signature_verified":false,"native_dependency_binding_established":false,"adoption_authorized":false}),
    )
}

#[test]
fn supplier_lock_inventory_does_not_authorize_rustfs_binary_adoption() -> Result {
    let (bom, provenance) = supplier_fixture();
    let summary = review_supplier(&bom, &provenance)?;
    for key in [
        "archive_bytes_verified",
        "image_executable_binding_established",
        "signature_verified",
        "native_dependency_binding_established",
        "adoption_authorized",
    ] {
        assert_eq!(summary[key], false);
    }
    Ok(())
}
fn supplier_fixture() -> (serde_json::Value, serde_json::Value) {
    use serde_json::json;
    (
        json!({"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"component":{"name":"rustfs","version":"1.0.4"},"tools":{"components":[{"name":"Cargo.lock"}]}},"components":[{"purl":"pkg:cargo/fixture@1"}]}),
        json!({"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"internalParameters":{"sha":"46337942d55f3a8e6a97b147ca98d9ea8115555d"}}},"subject":[{"name":"rustfs-linux-aarch64-musl-v1.0.4.zip","digest":{"sha256":"81414fd0e41969f4f5c2e0555951cee76d3f224c112c269c80f52b31276f187a"}},{"name":"rustfs-linux-x86_64-musl-v1.0.4.zip","digest":{"sha256":"4924ad4b699b9f59943051efedae2d1eb6d4cac503a1b0384c4b25f7c2c31b5c"}}]}),
    )
}
#[test]
fn supplier_review_rejects_changed_duplicate_and_unbound_identities() {
    let (bom, provenance) = supplier_fixture();
    let mut changed = bom.clone();
    changed["metadata"]["component"]["version"] = serde_json::json!("other");
    assert!(review_supplier(&changed, &provenance).is_err());
    let mut changed = provenance.clone();
    changed["subject"][0]["digest"]["sha256"] = serde_json::json!("other");
    assert!(review_supplier(&bom, &changed).is_err());
    let mut changed = provenance.clone();
    changed["subject"]
        .as_array_mut()
        .unwrap()
        .push(provenance["subject"][0].clone());
    assert!(review_supplier(&bom, &changed).is_err());
    let mut changed = provenance.clone();
    changed["predicate"]["buildDefinition"]["internalParameters"]["sha"] =
        serde_json::json!("other");
    assert!(review_supplier(&bom, &changed).is_err());
}
#[test]
#[ignore = "read-only review of fixed public supplier metadata captures, no execution or adoption"]
fn recorded_rustfs_supplier_metadata_is_not_a_binary_inventory_approval() -> Result {
    let root = xtask::root();
    let provenance = root.join(".work/dependency-rustfs-provenance.json");
    let bom = root.join(".work/dependency-rustfs-supplier.cdx.json");
    ensure(
        util::hash(&provenance)?
            == "sha256:a4758b844204dfb73c8f1cefee685796723a96d52f5c276bd187b71f9fef4ed1"
            && util::hash(&bom)?
                == "sha256:b328a37f6535773117332208f6e9c0b89c4cbb34d61452de062c039a9574213e",
        "Supplier capture changed",
    )?;
    let mut summary = review_supplier(&util::json(&bom)?, &util::json(&provenance)?)?;
    summary["sbom_digest"] = serde_json::json!(util::hash(&bom)?);
    summary["provenance_digest"] = serde_json::json!(util::hash(&provenance)?);
    let output = root.join(".work/rustfs-supplier-metadata-review.json");
    ensure(!output.exists(), "Refusing stale supplier review")?;
    util::write_json(&output, &summary)
}
