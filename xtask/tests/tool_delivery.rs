//! Opt-in delivery verification against the exact published scanner source.
#![forbid(unsafe_code)]
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
    time::Duration,
};
use xtask::{Result, ensure, images, util};
const SOURCE: &str = "13edb5277101befe100a435f5ade8da6ea3d40af";
const SYFT: &str = "sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c";
const GRYPE: &str = "sha256:3079a040326484d0b50ac28c7fc2fb25894a22170e81445ab90c400d091378e0";

fn blob_redirect(source: &str, location: &str) -> Result<reqwest::Url> {
    ensure(location.len() <= 8192, "Blob redirect location bound")?;
    let source = reqwest::Url::parse(source).map_err(|_| "Invalid registry source")?;
    let path = source.path();
    let blob = path.rsplit_once("/blobs/");
    ensure(
        source.scheme() == "https"
            && source.host_str() == Some("ghcr.io")
            && source.port_or_known_default() == Some(443)
            && source.username().is_empty()
            && source.password().is_none()
            && source.query().is_none()
            && source.fragment().is_none()
            && blob.is_some_and(|(prefix, id)| {
                ["/v2/prjxai/devsecops/syft", "/v2/prjxai/devsecops/grype"].contains(&prefix)
                    && images::is_digest(id)
            }),
        "Redirect only permitted for fixed registry config blobs",
    )?;
    let target = reqwest::Url::parse(location).map_err(|_| "Invalid blob redirect")?;
    ensure(
        target.scheme() == "https"
            && target.host_str() == Some("pkg-containers.githubusercontent.com")
            && target.port_or_known_default() == Some(443)
            && target.username().is_empty()
            && target.password().is_none()
            && target.fragment().is_none(),
        "Unapproved blob redirect target",
    )?;
    Ok(target)
}
fn blob_request(
    client: &reqwest::blocking::Client,
    target: reqwest::Url,
) -> reqwest::blocking::RequestBuilder {
    // Never forward the registry bearer token to the signed CDN URL.
    client
        .get(target)
        .header("User-Agent", "obsidian-sync-delivery-verifier/1")
}
fn get(client: &reqwest::blocking::Client, url: &str, token: Option<&str>) -> Result<Vec<u8>> {
    util::check_cancelled()?;
    let accept = if url.contains("/token?") {
        "application/json"
    } else {
        "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json"
    };
    let mut request = client
        .get(url)
        .header("User-Agent", "obsidian-sync-delivery-verifier/1")
        .header("Accept", accept);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    let mut response = request
        .send()
        .map_err(|_| "Registry metadata request failed")?;
    if response.status() == reqwest::StatusCode::TEMPORARY_REDIRECT {
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or("Missing blob redirect")?;
        let target = blob_redirect(url, location)?;
        response = blob_request(client, target)
            .send()
            .map_err(|_| "Blob CDN request failed")?;
    }
    // Client redirect policy is none: at most the single checked CDN hop above.
    if !response.status().is_success() {
        let phase = if url.contains("/token?") {
            "token"
        } else if url.contains("/blobs/") {
            "blob"
        } else {
            "manifest"
        };
        let status = response.status().as_u16();
        println!("Anonymous registry {phase} status {status}");
        return Err(format!("Anonymous registry {phase} status {status}").into());
    }
    let mut bytes = Vec::new();
    response
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Registry metadata read failed")?;
    ensure(
        bytes.len() <= 4 * 1024 * 1024,
        "Registry metadata byte limit",
    )?;
    Ok(bytes)
}
fn digest(bytes: &[u8], expected: &str) -> Result {
    ensure(
        images::is_digest(expected) && format!("sha256:{}", util::digest(bytes)) == expected,
        "Registry metadata digest mismatch",
    )
}
fn verify(tool: &str, expected: &str) -> Result {
    ensure(["syft", "grype"].contains(&tool), "Fixed scanner only")?;
    println!("Checking {tool} delivery without registry credentials");
    let root = xtask::root();
    let capture = root
        .join(".work/delivery-20261030")
        .join(format!("verified-{tool}-{}", util::random_hex()));
    fs::DirBuilder::new().mode(0o700).create(&capture)?;
    let supplier = root
        .parent()
        .ok_or("Missing workspace parent")?
        .join("devsecops/.work/delivery-20261030");
    let published = util::json(&supplier.join(format!("published-{tool}/release-status.json")))?;
    ensure(
        published["source_sha"] == SOURCE
            && published["tool"] == tool
            && published["manifest_digest"] == expected
            && published["status"] == "accepted-risk",
        "Publication record differs",
    )?;
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    // No credentials/cookies/config. The anonymous pull token never reaches logs/disk.
    let token_bytes = get(
        &client,
        &format!(
            "https://ghcr.io/token?service=ghcr.io&scope=repository:prjxai/devsecops/{tool}:pull"
        ),
        None,
    )?;
    let token = util::strict_json(&token_bytes)?;
    let token = token["token"]
        .as_str()
        .filter(|v| !v.is_empty() && v.len() <= 64 * 1024)
        .ok_or("Missing anonymous pull token")?;
    let base = format!("https://ghcr.io/v2/prjxai/devsecops/{tool}");
    let bytes = get(
        &client,
        &format!("{base}/manifests/{expected}"),
        Some(token),
    )?;
    digest(&bytes, expected)?;
    let index = util::strict_json(&bytes)?;
    ensure(index["schemaVersion"] == 2, "Registry index schema")?;
    let members = index["manifests"]
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or("Exactly two native members required")?;
    fs::write(capture.join("index.json"), &bytes)?;
    let mut seen = std::collections::BTreeSet::new();
    for member in members {
        let arch = member["platform"]["architecture"]
            .as_str()
            .ok_or("Missing architecture")?;
        ensure(
            ["amd64", "arm64"].contains(&arch)
                && member["platform"]["os"] == "linux"
                && seen.insert(arch),
            "Unexpected/duplicate native member",
        )?;
        let native = member["digest"]
            .as_str()
            .filter(|v| images::is_digest(v))
            .ok_or("Invalid member digest")?;
        let bytes = get(&client, &format!("{base}/manifests/{native}"), Some(token))?;
        digest(&bytes, native)?;
        let manifest = util::strict_json(&bytes)?;
        ensure(
            manifest["schemaVersion"] == 2
                && manifest.get("manifests").is_none()
                && manifest["layers"].as_array().is_some_and(|v| !v.is_empty()),
            "Native image manifest required",
        )?;
        fs::write(capture.join(format!("{arch}.manifest.json")), &bytes)?;
        let config = manifest["config"]["digest"]
            .as_str()
            .filter(|v| images::is_digest(v))
            .ok_or("Invalid config digest")?;
        let bytes = get(&client, &format!("{base}/blobs/{config}"), Some(token))?;
        digest(&bytes, config)?;
        let value = util::strict_json(&bytes)?;
        ensure(
            value["os"] == "linux"
                && value["architecture"] == arch
                && value["config"]["User"] == "65532:65532"
                && value["config"]["Labels"]["org.opencontainers.image.revision"] == SOURCE,
            "Source/platform/runtime config differs",
        )?;
        fs::write(capture.join(format!("{arch}.config.json")), &bytes)?;
        let catalog_dir = supplier.join(format!("{tool}-published-{arch}"));
        let summary = util::json(&catalog_dir.join("summary.json"))?;
        let catalog = catalog_dir.join(format!("{tool}.syft.json"));
        ensure(
            summary["source_sha"] == SOURCE
                && summary["arch"] == arch
                && summary["tools"].as_array().is_some_and(|v| v.len() == 1)
                && summary["tools"][0]["config_id"] == config
                && summary["tools"][0]["sbom_sha256"]
                    == util::hash(&catalog)?.trim_start_matches("sha256:"),
            "Published member differs from native catalog",
        )?;
    }
    // Empty Docker config prevents operator registry credentials from satisfying
    // what must also work anonymously. GitHub API authentication is separate.
    let docker = tempfile::tempdir()?;
    let reference = format!("oci://ghcr.io/prjxai/devsecops/{tool}@{expected}");
    let verified = util::output(
        util::cmd(
            "gh",
            &[
                "attestation",
                "verify",
                &reference,
                "--repo",
                "PRJXAI/devsecops",
                "--signer-workflow",
                "PRJXAI/devsecops/.github/workflows/tool.yml",
                "--signer-digest",
                SOURCE,
                "--source-digest",
                SOURCE,
                "--source-ref",
                "refs/heads/main",
                "--deny-self-hosted-runners",
                "--format",
                "json",
            ],
            &root,
        )
        .env("DOCKER_CONFIG", docker.path())
        .env_remove("GH_DEBUG"),
        180,
    )?;
    let result = util::strict_json(&verified)?;
    ensure(
        result.as_array().is_some_and(|v| {
            !v.is_empty()
                && v.iter().any(|r| {
                    r["verificationResult"]["statement"]["subject"]
                        .as_array()
                        .is_some_and(|a| {
                            a.iter().any(|s| {
                                s["name"] == format!("ghcr.io/prjxai/devsecops/{tool}")
                                    && s["digest"]["sha256"]
                                        == expected.trim_start_matches("sha256:")
                            })
                        })
                })
        }),
        "Verified provenance subject differs",
    )?;
    fs::write(capture.join("attestation.json"), &verified)?;
    util::write_json(
        &capture.join("summary.json"),
        &json!({"schema":1,"tool":tool,"source":SOURCE,"manifest_digest":expected,"anonymous_registry_access":true,"native_catalog_binding":true,"provenance_verified":true,"scope":"delivery verification; not vulnerability-free or deployment approval"}),
    )?;
    println!(
        "Verified {tool} anonymous access, both native config bindings and source/workflow provenance"
    );
    Ok(())
}

#[test]
#[ignore = "explicit published-source/anonymous/provenance investigation; no runtime acceptance"]
fn verify_fixed_scanner_delivery() -> Result {
    util::install_cancellation()?;
    let control = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let public = get(
        &control,
        "https://ghcr.io/token?service=ghcr.io&scope=repository:gitleaks/gitleaks:pull",
        None,
    )?;
    ensure(
        util::strict_json(&public)?["token"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "Public registry positive control failed",
    )?;
    println!("Known-public registry control passed");
    let syft = verify("syft", SYFT);
    let grype = verify("grype", GRYPE);
    syft.and(grype)
}

// Private access is a separate explicit qualification, never an automatic
// fallback that changes the result of the anonymous-access test above.
fn private_json(path: &Path, value: &Value) -> Result {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    Ok(())
}
fn carry_known_rules(old: &Value, published: &Value, tool: &str) -> Result<Vec<Value>> {
    ensure(
        ["syft", "grype"].contains(&tool),
        "Unsupported scanner migration",
    )?;
    let old_rules = old["rules"].as_array().ok_or("Missing original rules")?;
    let rules = published["rules"]
        .as_array()
        .ok_or("Missing published rules")?;
    ensure(
        !rules.is_empty() && rules.len() == old_rules.len(),
        "Scanner finding set changed",
    )?;
    let mut used = std::collections::BTreeSet::new();
    for rule in rules {
        let mut original_identity = rule["identity"].clone();
        ensure(
            original_identity["package"]["locations"] == json!([format!("/usr/local/bin/{tool}")]),
            "Unexpected packaged binary path",
        )?;
        original_identity["package"]["locations"] = json!([format!("/{tool}")]);
        let original = old_rules
            .iter()
            .find(|r| {
                r["identity"] == original_identity
                    && r["maximum_occurrences"] == rule["maximum_occurrences"]
            })
            .ok_or("New/changed advisory or occurrence budget")?;
        ensure(
            used.insert(
                original["id"]
                    .as_str()
                    .ok_or("Missing original rule identity")?,
            ),
            "Duplicate migrated finding",
        )?;
    }
    Ok(rules.clone())
}

#[test]
#[ignore = "explicit owner-authorized private delivery qualification and proposal, not public access or automatic approval"]
fn verify_fixed_private_scanner_delivery() -> Result {
    util::install_cancellation()?;
    let root = xtask::root();
    let supplier = root
        .parent()
        .ok_or("Missing workspace")?
        .join("devsecops/.work/delivery-20261030");
    let directory = root
        .join(".work/delivery-20261030")
        .join(format!("private-qualified-{}", util::random_hex()));
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let producer = util::json(
        &root
            .parent()
            .ok_or("Missing workspace")?
            .join("devsecops/inventory/accepted-risks.json"),
    )?;
    ensure(
        producer["decision"] == "owner-selected-stack-2026-10-30" && producer["schema"] == 1,
        "Unknown producer decision",
    )?;
    let mut policy = util::json(&root.join("xtask/src/accepted-risks.json"))?;
    let mut verified = Vec::new();
    for (tool, expected) in [("syft", SYFT), ("grype", GRYPE)] {
        let repository = format!("ghcr.io/prjxai/devsecops/{tool}");
        let reference = format!("{repository}@{expected}");
        let bytes = util::output(
            &mut util::cmd(
                "docker",
                &["buildx", "imagetools", "inspect", "--raw", &reference],
                &root,
            ),
            120,
        )?;
        digest(&bytes, expected)?;
        let index = util::strict_json(&bytes)?;
        ensure(index["schemaVersion"] == 2, "Invalid published index")?;
        let members = index["manifests"]
            .as_array()
            .filter(|v| v.len() == 2)
            .ok_or("Exactly two native members required")?;
        let status = util::json(&supplier.join(format!("published-{tool}/release-status.json")))?;
        ensure(
            status["source_sha"] == SOURCE
                && status["manifest_digest"] == expected
                && status["tool"] == tool
                && status["status"] == "accepted-risk",
            "Publication identity mismatch",
        )?;
        private_json(&directory.join(format!("{tool}.index.json")), &index)?;
        let mut arches = std::collections::BTreeSet::new();
        for member in members {
            let arch = member["platform"]["architecture"]
                .as_str()
                .ok_or("Missing architecture")?;
            ensure(
                member["platform"]["os"] == "linux"
                    && ["amd64", "arm64"].contains(&arch)
                    && arches.insert(arch),
                "Unexpected native platform",
            )?;
            let id = member["digest"]
                .as_str()
                .filter(|v| images::is_digest(v))
                .ok_or("Invalid native digest")?;
            let bytes = util::output(
                &mut util::cmd(
                    "docker",
                    &[
                        "buildx",
                        "imagetools",
                        "inspect",
                        "--raw",
                        &format!("{repository}@{id}"),
                    ],
                    &root,
                ),
                120,
            )?;
            digest(&bytes, id)?;
            let manifest = util::strict_json(&bytes)?;
            ensure(
                manifest["schemaVersion"] == 2
                    && manifest.get("manifests").is_none()
                    && manifest["layers"].as_array().is_some_and(|v| !v.is_empty()),
                "Invalid native manifest",
            )?;
            let config = manifest["config"]["digest"]
                .as_str()
                .filter(|v| images::is_digest(v))
                .ok_or("Invalid native config")?;
            let catalog_dir = supplier.join(format!("{tool}-published-{arch}"));
            let summary = util::json(&catalog_dir.join("summary.json"))?;
            let catalog = catalog_dir.join(format!("{tool}.syft.json"));
            ensure(
                summary["source_sha"] == SOURCE
                    && summary["arch"] == arch
                    && summary["tools"].as_array().is_some_and(|v| v.len() == 1)
                    && summary["tools"][0]["config_id"] == config
                    && summary["tools"][0]["sbom_sha256"]
                        == util::hash(&catalog)?.trim_start_matches("sha256:"),
                "Native catalog binding mismatch",
            )?;
            let platform = format!("linux/{arch}");
            let reference_image = producer["tools"][tool]["reference_image"]
                .as_str()
                .ok_or("Missing original image")?;
            let assets = policy["assets"].as_array().ok_or("Missing assets")?;
            let old = assets
                .iter()
                .find(|a| a["asset"] == reference_image && a["platform"] == platform)
                .ok_or("Missing original accepted asset")?;
            let mut rules = carry_known_rules(old, &producer["tools"][tool], tool)?;
            for rule in &mut rules {
                rule["id"] = json!(format!(
                    "devsecops-{tool}-{arch}-{}",
                    rule["id"].as_str().ok_or("Missing rule ID")?
                ));
            }
            let assessment = status["architectures"]
                .as_array()
                .ok_or("Missing native release status")?
                .iter()
                .find(|v| v["arch"] == arch)
                .ok_or("Missing native release status")?;
            ensure(
                assessment["risk"]["blocking"] == 0
                    && assessment["risk"]["accepted"] == rules.len()
                    && assessment["counts"]["ignoredMatches"] == 0,
                "Published accounting changed",
            )?;
            let asset = json!({"asset":format!("{repository}:sha-{SOURCE}@{expected}"),"platform":platform,"config_id":config,"reference_report_sha256":assessment["report_sha256"],"rules":rules});
            let assets = policy["assets"].as_array_mut().ok_or("Missing assets")?;
            if let Some(existing) = assets.iter().find(|a| a["config_id"] == config) {
                ensure(existing == &asset, "Existing migration differs")?;
            } else {
                assets.push(asset);
            }
            private_json(
                &directory.join(format!("{tool}.{arch}.manifest.json")),
                &manifest,
            )?;
            xtask::sbom::catalog_registry(
                &root,
                &format!("{repository}:sha-{SOURCE}@{expected}"),
                &platform,
                &directory,
                &format!("{tool}.{arch}"),
            )?;
            verified.push(json!({"tool":tool,"platform":platform,"manifest_digest":id,"config_digest":config,"source":SOURCE}));
        }
        let provenance = util::output(
            util::cmd(
                "gh",
                &[
                    "attestation",
                    "verify",
                    &format!("oci://{reference}"),
                    "--repo",
                    "PRJXAI/devsecops",
                    "--signer-workflow",
                    "PRJXAI/devsecops/.github/workflows/tool.yml",
                    "--signer-digest",
                    SOURCE,
                    "--source-digest",
                    SOURCE,
                    "--source-ref",
                    "refs/heads/main",
                    "--deny-self-hosted-runners",
                    "--format",
                    "json",
                ],
                &root,
            )
            .env_remove("GH_DEBUG"),
            180,
        )?;
        let provenance = util::strict_json(&provenance)?;
        ensure(
            provenance.as_array().is_some_and(|a| {
                a.iter().any(|v| {
                    v["verificationResult"]["statement"]["subject"]
                        .as_array()
                        .is_some_and(|s| {
                            s.iter().any(|s| {
                                s["name"] == repository
                                    && s["digest"]["sha256"]
                                        == expected.trim_start_matches("sha256:")
                            })
                        })
                })
            }),
            "Provenance subject mismatch",
        )?;
        private_json(
            &directory.join(format!("{tool}.attestation.json")),
            &provenance,
        )?;
    }
    private_json(
        &directory.join("proposed-consumer-risk-policy.json"),
        &policy,
    )?;
    private_json(
        &directory.join("summary.json"),
        &json!({"schema":1,"source":SOURCE,"access":"authenticated operator registry access verified; CI token grants and anonymous access remain separate","native_bindings":verified,"risk_scope":"Only exact existing identities/limits with reviewed binary relocation; proposal requires explicit integration","public_access_verified":false,"ci_access_verified":false}),
    )?;
    println!(
        "Verified both published private scanners and four native bindings; explicit policy proposal at {}",
        directory.display()
    );
    Ok(())
}

#[test]
fn scanner_migration_refuses_new_findings_versions_paths_and_duplicate_budgets() {
    let old = json!({"rules":[{"id":"old","identity":{"package":{"locations":["/syft"],"version":"1"},"vulnerability":{"id":"known"}},"maximum_occurrences":1}]});
    let rule = json!({"id":"published","identity":{"package":{"locations":["/usr/local/bin/syft"],"version":"1"},"vulnerability":{"id":"known"}},"maximum_occurrences":1});
    let good = json!({"rules":[rule]});
    assert!(carry_known_rules(&old, &good, "syft").is_ok());
    for (path, value) in [
        ("/rules/0/identity/vulnerability/id", json!("new")),
        ("/rules/0/identity/package/version", json!("2")),
        ("/rules/0/identity/package/locations", json!(["/elsewhere"])),
        ("/rules/0/maximum_occurrences", json!(2)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(carry_known_rules(&old, &bad, "syft").is_err());
    }
    let mut bad = good.clone();
    bad["rules"]
        .as_array_mut()
        .unwrap()
        .push(good["rules"][0].clone());
    assert!(carry_known_rules(&old, &bad, "syft").is_err());
}

#[test]
fn production_scanners_are_the_exact_qualified_devsecops_images() {
    assert_eq!(
        xtask::sbom::SYFT,
        format!("ghcr.io/prjxai/devsecops/syft:sha-{SOURCE}@{SYFT}")
    );
    assert_eq!(
        xtask::grype::GRYPE,
        format!("ghcr.io/prjxai/devsecops/grype:sha-{SOURCE}@{GRYPE}")
    );
}

#[test]
fn config_blob_redirect_is_bounded_https_allowlisted_and_credential_free() {
    let source = format!(
        "https://ghcr.io/v2/prjxai/devsecops/syft/blobs/sha256:{}",
        "a".repeat(64)
    );
    let good =
        "https://pkg-containers.githubusercontent.com/ghcr1/blobs/config?synthetic-signature=test";
    let target = blob_redirect(&source, good).unwrap();
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let request = blob_request(&client, target).build().unwrap();
    assert!(
        !request
            .headers()
            .contains_key(reqwest::header::AUTHORIZATION)
    );
    for bad in [
        "http://pkg-containers.githubusercontent.com/blob",
        "https://127.0.0.1/blob",
        "https://pkg-containers.githubusercontent.com.evil.invalid/blob",
        "https://pkg-containers.githubusercontent.com:8443/blob",
        "https://user:password@pkg-containers.githubusercontent.com/blob",
        "https://pkg-containers.githubusercontent.com/blob#fragment",
        "//pkg-containers.githubusercontent.com/blob",
    ] {
        assert!(blob_redirect(&source, bad).is_err());
    }
    assert!(blob_redirect(&source, &"x".repeat(8193)).is_err());
    for bad in [
        source.replace("ghcr.io/", "other.invalid/"),
        source.replace("/blobs/", "/manifests/"),
        source.replace("/syft/", "/other/"),
        source.replace("https:", "http:"),
    ] {
        assert!(blob_redirect(&bad, good).is_err());
    }
}
#[test]
fn metadata_digest_validation_rejects_substitution_and_wrong_identity_types() {
    let bytes = b"public synthetic manifest";
    assert!(digest(bytes, &format!("sha256:{}", util::digest(bytes))).is_ok());
    for wrong in [
        String::from("latest"),
        format!("sha256:{}", "0".repeat(64)),
        util::digest(bytes),
    ] {
        assert!(digest(bytes, &wrong).is_err());
    }
}
