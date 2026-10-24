use crate::{Result, ensure, images, security, util};
use serde_json::{Value, json};
use std::{collections::BTreeSet, fs, path::Path};

pub const SYFT: &str = "anchore/syft:v1.55.0-nonroot@sha256:ec5bdbc745485920c6f444239f0c09ed87b3c4c165ff9433f95bc66b3500fbf9";
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
        &format!("{}:/reports", output.display()),
        "--volume",
        &format!("{}:{mountpoint}:ro", source.display()),
        SYFT,
        target,
        "-o",
        &format!("cyclonedx-json=/reports/{name}.cdx.json"),
        "-o",
        &format!("spdx-json=/reports/{name}.spdx.json"),
    ]);
    util::logged(&mut c, &output.join(format!("{name}.log")), 600)?;
    validate_output(output, name)
}
pub fn validate_output(output: &Path, name: &str) -> Result {
    for (suffix, key) in [("cdx.json", "components"), ("spdx.json", "packages")] {
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
    }
    scan(root, "dir:/source", &source, "/source", &output, "source")?;
    source_complete(
        root,
        util::json(&output.join("source.cdx.json"))?["components"]
            .as_array()
            .ok_or("Missing source inventory")?,
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
        "builder.cdx.json",
        "builder.spdx.json",
        "source.cdx.json",
        "source.spdx.json",
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
    println!("Generated six SPDX/CycloneDX inventories, native identity and bound materials");
    Ok(())
}
