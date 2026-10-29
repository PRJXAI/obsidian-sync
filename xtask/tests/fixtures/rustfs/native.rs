//! A fixed local prototype. Never selected by the production CLI or image inventory.
use super::*;
use crate::{grype, images, sbom, security};
use serde_json::json;

const FIXTURE_HASH: &str = "d1c4297d34f1b7b2a3a79eebb14d13908b88abb7164b9aa9f47b6f50607c0a54";

fn fixture(bytes: &[u8]) -> Result {
    ensure(
        util::digest(bytes) == FIXTURE_HASH,
        "Changed RustFS prototype",
    )
}

// A label or base-package catalog cannot establish the shipped Rust payload.
// This is a necessary main-payload check, not full dependency/native coverage.
fn payload_catalogued(catalog: &serde_json::Value) -> Result {
    ensure(
        catalog["artifacts"].as_array().is_some_and(|a| {
            a.iter().any(|v| {
                v["name"] == "rustfs"
                    && v["version"] == "1.0.4"
                    && v["type"] == "rust-crate"
                    && v["locations"]
                        .as_array()
                        .is_some_and(|locations| locations.iter().any(|l| l["path"] == "/rustfs"))
            })
        }),
        "Prototype catalog omitted RustFS payload",
    )
}

#[test]
fn base_packages_and_image_labels_do_not_prove_rustfs_payload_coverage() {
    for catalog in [
        json!({}),
        json!({"artifacts":[]}),
        json!({"artifacts":[{"name":"ca-certificates-bundle"}]}),
        json!({"artifacts":[{"name":"RustFS","version":"v1.0.4","type":"binary"}]}),
    ] {
        assert!(payload_catalogued(&catalog).is_err());
    }
    let valid = json!({"artifacts":[{"name":"rustfs","version":"1.0.4","type":"rust-crate","locations":[{"path":"/rustfs"}]}]});
    payload_catalogued(&valid).unwrap();
    for (key, value) in [
        ("name", json!("other")),
        ("version", json!("1.0.3")),
        ("type", json!("apk")),
        ("locations", json!([{ "path":"/unrelated" }])),
    ] {
        let mut changed = valid.clone();
        changed["artifacts"][0][key] = value;
        assert!(payload_catalogued(&changed).is_err());
    }
}

#[test]
fn fixed_rustfs_fixture_cannot_change_suppliers_or_add_shell_glue() {
    let bytes = include_bytes!("Dockerfile");
    fixture(bytes).unwrap();
    let mut changed = bytes.to_vec();
    changed.extend_from_slice(b"\nRUN echo unsafe\n");
    assert!(fixture(&changed).is_err());
    assert!(fixture(&[]).is_err());
}

#[test]
#[ignore = "builds/scans a fixed local prototype and runs real S3/client fixtures, no adoption"]
fn native_minimal_rustfs_preserves_s3_and_real_clients() -> Result {
    let root = crate::root();
    util::install_cancellation()?;
    let endpoint = util::local_docker_endpoint(&root)?;
    fixture(include_bytes!("Dockerfile"))?;
    let output = root.join(".work/security/rustfs-minimal-evaluation");
    ensure(!output.exists(), "Refusing stale prototype evaluation")?;
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    let iid = output.join("image.id");
    util::logged(
        util::cmd(
            "docker",
            &[
                "--host",
                &endpoint,
                "buildx",
                "build",
                "--builder",
                "default",
                "--load",
                "--iidfile",
            ],
            &root,
        )
        .env_remove("DOCKER_CONTEXT")
        .env_remove("BUILDX_BUILDER")
        .env_remove("BUILDKIT_HOST")
        .arg(&iid)
        .arg(root.join("xtask/tests/fixtures/rustfs")),
        &output.join("build.log"),
        300,
    )?;
    let image = String::from_utf8(util::read(&iid, 256)?)?.trim().to_owned();
    ensure(images::is_digest(&image), "Invalid prototype image ID")?;
    let inspected = images::inspect(&root, &image)?;
    let native = util::text(
        &mut util::cmd(
            "docker",
            &["version", "--format", "{{.Server.Arch}}"],
            &root,
        ),
        30,
    )?;
    ensure(
        inspected["Architecture"] == native && inspected["Os"] == "linux",
        "Prototype is not native Linux",
    )?;
    ensure(
        inspected["Config"]["User"] == "65532:65532"
            && inspected["Config"]["Entrypoint"] == json!(["/rustfs"]),
        "Prototype configuration drift",
    )?;
    // Inspect only ELF headers using a bounded direct supplier utility, no shell
    // script or operator mount. Running the final binary also proves its loader
    // requirements can be satisfied by the minimal base.
    let supplier = include_str!("Dockerfile")
        .lines()
        .find_map(|l| {
            l.strip_prefix("FROM ")
                .and_then(|v| v.strip_suffix(" AS supplier"))
        })
        .ok_or("Missing supplier")?;
    let container = util::Container::new(&root, "rustfs-elf");
    let mut c = util::cmd("docker", &[], &root);
    c.args(security::sandbox_args(&container.name)).args([
        "--network",
        "none",
        "--entrypoint",
        "/bin/busybox",
        supplier,
        "dd",
        "if=/usr/bin/rustfs",
        "bs=65536",
        "count=1",
    ]);
    images::verify_elf(&util::output(&mut c, 60)?)?;
    let container = util::Container::new(&root, "rustfs-version");
    let mut c = util::cmd("docker", &[], &root);
    c.args(security::sandbox_args(&container.name)).args([
        "--network",
        "none",
        &image,
        "--version",
    ]);
    let version = util::text(&mut c, 60)?;
    ensure(version.contains("1.0.4"), "Unexpected RustFS version")?;
    let compose_source = fs::read_to_string(root.join("docker-compose.test-s3.yml"))?;
    let image_line = compose_source
        .lines()
        .find(|l| l.trim_start().starts_with("image:"))
        .ok_or("Missing service image")?;
    let compose = output.join("compose.yml");
    fs::write(
        &compose,
        compose_source.replacen(image_line, &format!("    image: {image}"), 1),
    )?;
    let functional = s3_fixture(&root, compose);
    let archive = output.join("image.tar");
    let materials = images::export(&root, &image, &archive)?;
    sbom::scan(
        &root,
        "docker-archive:/input/image.tar",
        &archive,
        "/input/image.tar",
        &output,
        "candidate",
    )?;
    let catalog = util::json(&output.join("candidate.syft.json"))?;
    ensure(
        grype::image_subject(&catalog)?["ImageID"] == materials["config_digest"],
        "Prototype catalog substitution",
    )?;
    let payload = payload_catalogued(&catalog);
    let findings = if payload.is_ok() {
        let cache = root.join(".work/grype-cache");
        grype::database(&root, &cache, &output)?;
        Some(grype::scan(
            &root,
            &output.join("candidate.syft.json"),
            &output,
            &cache,
            "candidate",
        )?)
    } else {
        None
    };
    util::write_json(
        &output.join("summary.json"),
        &json!({
            "image_id":image,"materials":materials,"architecture":native,
            "created_at":chrono::Utc::now().to_rfc3339(),"fixture_sha256":FIXTURE_HASH,
            "functional":if functional.is_ok() {"pass"} else {"error"},
            "payload_inventory":if payload.is_ok() {"present-not-complete"} else {"missing"},
            "observed_packages":catalog["artifacts"].as_array().map(Vec::len),
            "sbom_digest":util::hash(&output.join("candidate.syft.json"))?,
            "findings":findings,"cataloger_image":sbom::SYFT,"scanner_image":grype::GRYPE,
            "complete_native_dependency_inventory":false,"complete_source_notice_provenance_review":false,
            "adoption_authorized":false
        }),
    )?;
    functional?;
    payload?;
    ensure(findings == Some(0), "Prototype findings remain blocking")
}
