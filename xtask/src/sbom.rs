use crate::{Result, ensure, images, security, util};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path};

pub const SYFT: &str = "ghcr.io/prjxai/devsecops/syft:sha-13edb5277101befe100a435f5ade8da6ea3d40af@sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c";
pub const SOURCE_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "xtask/Cargo.toml",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "LICENSE",
    "tests/compat/package.json",
    "tests/compat/package-lock.json",
];
pub fn stage_source(root: &Path, destination: &Path) -> Result<Vec<Value>> {
    let mut materials = Vec::new();
    for relative in SOURCE_FILES {
        let source = util::regular_source(root, Path::new(relative))?;
        let target = destination.join(relative);
        fs::create_dir_all(target.parent().ok_or("Missing parent")?)?;
        fs::write(&target, util::read(&source, util::JSON_LIMIT)?)?;
        materials.push(json!({"path":relative,"digest":util::hash(&target)?}));
    }
    Ok(materials)
}
pub fn source_complete(root: &Path, components: &[Value]) -> Result {
    let entries = |ecosystem: &str| -> BTreeSet<(String, String)> {
        let prefix = format!("pkg:{ecosystem}/");
        components
            .iter()
            .filter_map(|v| {
                let raw = v["purl"].as_str()?.strip_prefix(&prefix)?;
                let (name, version) = raw.rsplit_once('@')?;
                Some((
                    percent_encoding::percent_decode_str(name)
                        .decode_utf8()
                        .ok()?
                        .into_owned(),
                    percent_encoding::percent_decode_str(version.split('?').next()?)
                        .decode_utf8()
                        .ok()?
                        .into_owned(),
                ))
            })
            .collect()
    };
    let cargo: toml::Value = toml::from_str(&fs::read_to_string(root.join("Cargo.lock"))?)?;
    let mut required = BTreeSet::new();
    for package in cargo["package"]
        .as_array()
        .ok_or("Missing locked packages")?
    {
        if package.get("source").is_some() {
            required.insert((
                package["name"].as_str().ok_or("Invalid package")?.into(),
                package["version"].as_str().ok_or("Invalid version")?.into(),
            ));
        }
    }
    ensure(
        required.is_subset(&entries("cargo")),
        "Source SBOM omitted locked Rust dependencies",
    )?;
    let npm = util::json(&root.join("tests/compat/package-lock.json"))?;
    let mut required = BTreeSet::new();
    for (path, package) in npm["packages"]
        .as_object()
        .ok_or("Missing npm lock graph")?
    {
        if !path.is_empty() && package.get("link") != Some(&Value::Bool(true)) {
            required.insert((
                package["name"]
                    .as_str()
                    .unwrap_or(
                        path.rsplit("node_modules/")
                            .next()
                            .ok_or("Invalid package path")?,
                    )
                    .into(),
                package["version"]
                    .as_str()
                    .ok_or("Invalid npm version")?
                    .into(),
            ));
        }
    }
    ensure(
        required.is_subset(&entries("npm")),
        "Source SBOM omitted locked npm development dependencies",
    )
}
pub fn scan(
    root: &Path,
    target: &str,
    source: &Path,
    mountpoint: &str,
    output: &Path,
    name: &str,
) -> Result {
    let temporary = tempfile::Builder::new()
        .prefix("syft-output-")
        .tempdir_in(root.join(".work"))?;
    let container = util::Container::new(root, "sync-sbom");
    let mut c = util::cmd("docker", &[], root);
    c.args(security::sandbox_args(&container.name));
    c.args([
        "--network",
        "none",
        "--env",
        "XDG_CACHE_HOME=/tmp/cache",
        "--env",
        "SYFT_PARALLELISM=4",
        "--env",
        "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true",
        "--env",
        "SYFT_CHECK_FOR_APP_UPDATE=false",
        "--volume",
        &format!("{}:/reports", temporary.path().display()),
        "--volume",
        &format!("{}:{mountpoint}:ro", source.display()),
        SYFT,
        target,
        "-o",
        &format!("cyclonedx-json=/reports/{name}.cdx.json"),
        "-o",
        &format!("spdx-json=/reports/{name}.spdx.json"),
        "-o",
        &format!("syft-json=/reports/{name}.syft.json"),
    ]);
    util::logged(&mut c, &output.join(format!("{name}.log")), 600)?;
    publish_catalog(temporary.path(), output, name)
}
fn publish_catalog(temporary: &Path, output: &Path, name: &str) -> Result {
    validate_output(temporary, name)?;
    for suffix in ["syft.json", "cdx.json", "spdx.json"] {
        let file = format!("{name}.{suffix}");
        fs::write(
            output.join(&file),
            util::read(&temporary.join(file), util::JSON_LIMIT)?,
        )?;
    }
    Ok(())
}
fn registry_metadata(bytes: &[u8], expected: &str) -> Result<Value> {
    ensure(
        bytes.len() <= 4 * 1024 * 1024
            && images::is_digest(expected)
            && format!("sha256:{}", util::digest(bytes)) == expected,
        "Registry metadata digest/bound mismatch",
    )?;
    let value = util::strict_json(bytes)?;
    ensure(value["schemaVersion"] == 2, "Registry metadata schema")?;
    Ok(value)
}
fn scanner_member(index: &Value, platform: &str) -> Result<String> {
    ensure(
        ["linux/amd64", "linux/arm64"].contains(&platform),
        "Unsupported scanner platform",
    )?;
    let members = index["manifests"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or("Exactly two scanner members required")?;
    let mut seen = BTreeSet::new();
    let mut selected = None;
    for member in members {
        let arch = member["platform"]["architecture"]
            .as_str()
            .ok_or("Missing native architecture")?;
        ensure(
            member["platform"]["os"] == "linux"
                && ["amd64", "arm64"].contains(&arch)
                && seen.insert(arch),
            "Foreign/duplicate scanner platform",
        )?;
        let digest = member["digest"]
            .as_str()
            .filter(|v| images::is_digest(v))
            .ok_or("Invalid scanner member digest")?;
        if platform == format!("linux/{arch}") {
            selected = Some(digest.to_owned());
        }
    }
    selected.ok_or_else(|| "Missing scanner platform".into())
}
fn private_scanner_material(
    material: &Value,
    config: &str,
    native: &str,
    platform: &str,
) -> Result {
    let (os, arch) = platform.split_once('/').ok_or("Invalid platform")?;
    // Classic Docker exposes the config ID; the containerd image store exposes
    // the native manifest ID. Neither permits substituting the index identity.
    ensure(
        material["config_digest"] == config
            && (material["image_id"] == config || material["image_id"] == native)
            && material["os"] == os
            && material["architecture"] == arch,
        "Private scanner archive/platform mismatch",
    )
}
fn catalog_private_scanner(
    root: &Path,
    image: &str,
    platform: &str,
    output: &Path,
    name: &str,
) -> Result {
    ensure(
        [SYFT, crate::grype::GRYPE].contains(&image),
        "Qualified private scanner only",
    )?;
    util::local_docker(root)?;
    let (tag, digest) = image.split_once('@').ok_or("Missing scanner digest")?;
    let repository = tag.rsplit_once(':').ok_or("Missing scanner source tag")?.0;
    let fetch = |reference: &str| -> Result<Vec<u8>> {
        util::output(
            &mut util::cmd(
                "docker",
                &["buildx", "imagetools", "inspect", "--raw", reference],
                root,
            ),
            120,
        )
    };
    let index = registry_metadata(&fetch(image)?, digest)?;
    let native = scanner_member(&index, platform)?;
    // Pull the native digest, never retag the index used to execute the scanner.
    let reference = format!("{repository}@{native}");
    let manifest = registry_metadata(&fetch(&reference)?, &native)?;
    let config = manifest["config"]["digest"]
        .as_str()
        .filter(|v| images::is_digest(v))
        .ok_or("Invalid native configuration")?;
    ensure(
        manifest.get("manifests").is_none()
            && manifest["layers"].as_array().is_some_and(|v| !v.is_empty()),
        "Expected native scanner manifest",
    )?;
    util::run(
        &mut util::cmd(
            "docker",
            &["pull", "--platform", platform, &reference],
            root,
        ),
        180,
    )?;
    let temporary = tempfile::Builder::new()
        .prefix("private-scanner-")
        .tempdir_in(root.join(".work"))?;
    let archive = temporary.path().join("image.tar");
    // A containerd daemon identifier is not an unambiguous save selector.
    // Export the exact native reference and platform, not a daemon/index ID.
    let inspected = images::inspect(root, &reference)?;
    util::run(
        &mut util::cmd(
            "docker",
            &[
                "image",
                "save",
                "--platform",
                platform,
                "--output",
                archive.to_str().ok_or("Invalid archive path")?,
                &reference,
            ],
            root,
        ),
        180,
    )?;
    let material = images::archive_material(&inspected, &archive)?;
    let (os, arch) = platform.split_once('/').ok_or("Invalid platform")?;
    private_scanner_material(&material, config, &native, platform)?;
    scan(
        root,
        "docker-archive:/images/image.tar",
        &archive,
        "/images/image.tar",
        output,
        name,
    )?;
    let subject =
        crate::grype::image_subject(&util::json(&output.join(format!("{name}.syft.json")))?)?;
    ensure(
        subject["ImageID"] == config
            && subject["DiffIDs"] == material["layers"]
            && subject["os"] == os
            && subject["architecture"] == arch,
        "Private scanner catalog differs from original archive",
    )
}

pub fn catalog_registry(
    root: &Path,
    image: &str,
    platform: &str,
    output: &Path,
    name: &str,
) -> Result {
    if [SYFT, crate::grype::GRYPE].contains(&image) {
        return catalog_private_scanner(root, image, platform, output, name);
    }
    let temporary = tempfile::Builder::new()
        .prefix("syft-registry-output-")
        .tempdir_in(root.join(".work"))?;
    let container = util::Container::new(root, "sync-syft-registry");
    let mut c = util::cmd("docker", &[], root);
    c.args(security::sandbox_args(&container.name));
    c.args([
        "--env",
        "SYFT_CHECK_FOR_APP_UPDATE=false",
        "--env",
        "SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true",
        "--env",
        "SYFT_PARALLELISM=4",
        "--volume",
        &format!("{}:/reports", temporary.path().display()),
        SYFT,
        &format!("registry:{image}"),
        "--platform",
        platform,
        "-o",
        &format!("syft-json=/reports/{name}.syft.json"),
        "-o",
        &format!("cyclonedx-json=/reports/{name}.cdx.json"),
        "-o",
        &format!("spdx-json=/reports/{name}.spdx.json"),
    ]);
    util::logged(&mut c, &output.join(format!("{name}.syft.log")), 600)?;
    publish_catalog(temporary.path(), output, name)
}
pub fn validate_output(output: &Path, name: &str) -> Result {
    for (suffix, key) in [
        ("cdx.json", "components"),
        ("spdx.json", "packages"),
        ("syft.json", "artifacts"),
    ] {
        ensure(
            util::json(&output.join(format!("{name}.{suffix}")))?[key]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
            "Empty SBOM",
        )?;
    }
    Ok(())
}
pub fn generate(
    root: &Path,
    runtime: &str,
    builder: &str,
    archives: Option<(&Path, &Path)>,
) -> Result {
    util::local_docker(root)?;
    let output = root.join(".work/sbom");
    fs::create_dir_all(&output)?;
    fs::set_permissions(&output, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let manifest = output.join("materials.json");
    if manifest.exists() {
        fs::remove_file(&manifest)?;
    }
    let temporary = tempfile::Builder::new()
        .prefix("sbom-")
        .tempdir_in(root.join(".work"))?;
    let source = temporary.path().join("source");
    fs::create_dir(&source)?;
    let dependencies = stage_source(root, &source)?;
    let mut image_materials = serde_json::Map::new();
    for (name, image, provided) in [
        ("runtime", runtime, archives.map(|x| x.0)),
        ("builder", builder, archives.map(|x| x.1)),
    ] {
        let generated = temporary.path().join(format!("{name}.tar"));
        let archive = provided.unwrap_or(&generated);
        let material = if provided.is_some() {
            images::archive_material(&images::inspect(root, image)?, archive)?
        } else {
            images::export(root, image, archive)?
        };
        image_materials.insert(name.into(), material);
        scan(
            root,
            &format!("docker-archive:/images/{name}.tar"),
            archive,
            &format!("/images/{name}.tar"),
            &output,
            name,
        )?;
        let catalog = util::json(&output.join(format!("{name}.syft.json")))?;
        let subject = crate::grype::image_subject(&catalog)?;
        ensure(
            subject["ImageID"] == image_materials[name]["config_digest"]
                && subject["DiffIDs"] == image_materials[name]["layers"],
            "Catalog/archive configuration or layers differ",
        )?;
    }
    scan(root, "dir:/source", &source, "/source", &output, "source")?;
    source_complete(
        root,
        util::json(&output.join("source.cdx.json"))?["components"]
            .as_array()
            .ok_or("Missing source inventory")?,
    )?;
    source_complete(
        root,
        util::json(&output.join("source.syft.json"))?["artifacts"]
            .as_array()
            .ok_or("Missing native source inventory")?,
    )?;
    fs::write(
        output.join("native-toolchain.txt"),
        security::native_identity(
            root,
            image_materials["builder"]["image_id"]
                .as_str()
                .ok_or("Missing builder ID")?,
        )?,
    )?;
    let artifacts = [
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
    ]
    .into_iter()
    .map(|name| Ok(json!({"path":name,"digest":util::hash(&output.join(name))?})))
    .collect::<Result<Vec<_>>>()?;
    let sources = util::tracked(root)?
        .into_iter()
        .filter(|relative| {
            !root
                .join(relative)
                .symlink_metadata()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
        })
        .map(|relative| {
            let path = util::regular_source(root, &relative)?;
            Ok(json!({"path":relative,"digest":util::hash(&path)?}))
        })
        .collect::<Result<Vec<_>>>()?;
    let revision = util::text(&mut util::cmd("git", &["rev-parse", "HEAD"], root), 30)?;
    let dirty = !util::output(
        &mut util::cmd(
            "git",
            &["status", "--porcelain", "--untracked-files=normal"],
            root,
        ),
        30,
    )?
    .is_empty();
    util::write_json(
        &manifest,
        &json!({"schema_version":1,"generator_image":SYFT,"source_revision":revision,"source_tree_digest":format!("sha256:{}",util::digest(&serde_json::to_vec(&sources)?)),"working_tree_dirty":dirty,"dependency_inputs":dependencies,"images":image_materials,"artifacts":artifacts,"limitations":["Unsigned inventory, not builder trust or release authorization","Native/toolchain patches require separate review","Lock graph includes test and target-specific dependencies"]}),
    )?;
    println!("Generated nine Syft/SPDX/CycloneDX inventories, native identity and bound materials");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_scanner_material_keeps_manifest_config_and_daemon_levels_distinct() {
        let config = format!("sha256:{}", "a".repeat(64));
        let native = format!("sha256:{}", "b".repeat(64));
        let good =
            json!({"config_digest":config,"image_id":config,"os":"linux","architecture":"arm64"});
        assert!(private_scanner_material(&good, &config, &native, "linux/arm64").is_ok());
        let mut containerd = good.clone();
        containerd["image_id"] = json!(native);
        assert!(private_scanner_material(&containerd, &config, &native, "linux/arm64").is_ok());
        for (pointer, value) in [
            ("/config_digest", json!(native)),
            ("/image_id", json!(format!("sha256:{}", "c".repeat(64)))),
            ("/os", json!("windows")),
            ("/architecture", json!("amd64")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(private_scanner_material(&bad, &config, &native, "linux/arm64").is_err());
        }
    }
    #[test]
    fn private_scanner_metadata_rejects_substitution_oversize_and_foreign_members() {
        let a = format!("sha256:{}", "a".repeat(64));
        let b = format!("sha256:{}", "b".repeat(64));
        let index = json!({"schemaVersion":2,"manifests":[{"digest":a,"platform":{"os":"linux","architecture":"amd64"}},{"digest":b,"platform":{"os":"linux","architecture":"arm64"}}]});
        let bytes = serde_json::to_vec(&index).unwrap();
        let digest = format!("sha256:{}", util::digest(&bytes));
        assert!(registry_metadata(&bytes, &digest).is_ok());
        assert!(registry_metadata(&bytes, &a).is_err());
        assert!(registry_metadata(&vec![b' '; 4 * 1024 * 1024 + 1], &digest).is_err());
        assert_eq!(scanner_member(&index, "linux/amd64").unwrap(), a);
        assert_eq!(scanner_member(&index, "linux/arm64").unwrap(), b);
        assert!(scanner_member(&index, "windows/amd64").is_err());
        for (pointer, value) in [
            ("/manifests/0/platform/os", json!("windows")),
            ("/manifests/0/platform/architecture", json!("arm64")),
            ("/manifests/0/digest", json!("latest")),
        ] {
            let mut bad = index.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(scanner_member(&bad, "linux/arm64").is_err());
        }
        let mut bad = index.clone();
        bad["manifests"]
            .as_array_mut()
            .unwrap()
            .push(index["manifests"][0].clone());
        assert!(scanner_member(&bad, "linux/arm64").is_err());
        assert!(scanner_member(&json!({"schemaVersion":2}), "linux/amd64").is_err());
        let bytes = br#"{"schemaVersion":1}"#;
        assert!(registry_metadata(bytes, &format!("sha256:{}", util::digest(bytes))).is_err());
        assert!(
            catalog_private_scanner(
                Path::new("unused"),
                "foreign",
                "linux/amd64",
                Path::new("unused"),
                "image"
            )
            .is_err()
        );
    }
}
