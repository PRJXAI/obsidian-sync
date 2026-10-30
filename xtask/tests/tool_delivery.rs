//! Opt-in delivery verification against the exact published scanner source.
#![forbid(unsafe_code)]
use serde_json::json;
use std::{fs, io::Read, os::unix::fs::DirBuilderExt, time::Duration};
use xtask::{Result, ensure, images, util};
const SOURCE: &str = "13edb5277101befe100a435f5ade8da6ea3d40af";
const SYFT: &str = "sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c";
const GRYPE: &str = "sha256:3079a040326484d0b50ac28c7fc2fb25894a22170e81445ab90c400d091378e0";

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
    let response = request
        .send()
        .map_err(|_| "Registry metadata request failed")?;
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
