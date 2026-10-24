use crate::{Result, ensure, util};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use std::{io::Read, path::Path};

pub fn inspect(root: &Path, image: &str) -> Result<Value> {
    let values: Value = serde_json::from_slice(&util::output(
        &mut util::cmd("docker", &["image", "inspect", image], root),
        30,
    )?)?;
    Ok(values
        .as_array()
        .and_then(|v| v.first())
        .ok_or("Missing inspected image")?
        .clone())
}
pub fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn member(path: &Path, name: &str, limit: u64) -> Result<Vec<u8>> {
    let mut archive = tar::Archive::new(util::bounded_file(path, 8 * 1024 * 1024 * 1024)?);
    let mut result = None;
    for item in archive.entries()? {
        let mut item = item?;
        if item.path()?.as_ref() == Path::new(name) {
            ensure(
                result.is_none() && item.header().entry_type().is_file() && item.size() <= limit,
                "Invalid/duplicate archive member",
            )?;
            let mut bytes = Vec::new();
            item.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
            ensure(bytes.len() as u64 <= limit, "Oversized archive member")?;
            result = Some(bytes);
        }
    }
    result.ok_or_else(|| "Missing archive member".into())
}
pub fn saved_config(path: &Path) -> Result<Vec<u8>> {
    let manifests: Value = serde_json::from_slice(&member(path, "manifest.json", 1024 * 1024)?)?;
    let manifests = manifests.as_array().ok_or("Invalid manifest")?;
    ensure(manifests.len() == 1, "Expected one image")?;
    let name = manifests[0]["Config"].as_str().ok_or("Missing config")?;
    ensure(
        Path::new(name)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_))),
        "Escaping archive config",
    )?;
    member(path, name, 1024 * 1024)
}
pub fn export(root: &Path, image: &str, destination: &Path) -> Result<Value> {
    let inspected = inspect(root, image)?;
    let id = inspected["Id"].as_str().ok_or("Missing image ID")?;
    ensure(is_digest(id), "Invalid image identity")?;
    util::run(
        &mut util::cmd(
            "docker",
            &[
                "save",
                id,
                "--output",
                destination.to_str().ok_or("Invalid archive path")?,
            ],
            root,
        ),
        180,
    )?;
    archive_material(&inspected, destination)
}
pub fn archive_material(inspected: &Value, archive: &Path) -> Result<Value> {
    let config = saved_config(archive)?;
    let value: Value = serde_json::from_slice(&config)?;
    ensure(
        value["rootfs"]["diff_ids"].is_array()
            && value["rootfs"]["diff_ids"] == inspected["RootFS"]["Layers"],
        "Saved/inspected layer mismatch",
    )?;
    Ok(
        json!({"image_id":inspected["Id"],"config_digest":format!("sha256:{}",util::digest(&config)),"layers":value["rootfs"]["diff_ids"],"os":inspected["Os"],"architecture":inspected["Architecture"],"archive_digest":util::hash(archive)?}),
    )
}
pub fn verify_content(
    report: &Value,
    inspected: &Value,
    config: &[u8],
    now: DateTime<Utc>,
) -> Result<String> {
    crate::evidence::fresh(
        report["CreatedAt"].as_str().ok_or("Missing report time")?,
        now,
    )?;
    let results = report["Results"].as_array().ok_or("Missing scan results")?;
    ensure(
        !results.is_empty()
            && results.iter().all(|x| {
                x.is_object()
                    && (x.get("Vulnerabilities").is_none()
                        || x["Vulnerabilities"]
                            .as_array()
                            .is_some_and(|v| v.is_empty()))
            }),
        "Complete clean runtime scan required",
    )?;
    let expected = &report["Metadata"];
    ensure(
        expected["ImageID"].as_str().is_some_and(is_digest)
            && expected["ImageID"] == format!("sha256:{}", util::digest(config)),
        "Scanned configuration mismatch",
    )?;
    let layers = &expected["DiffIDs"];
    ensure(
        layers.as_array().is_some_and(|v| !v.is_empty())
            && *layers == inspected["RootFS"]["Layers"],
        "Scanned layers mismatch",
    )?;
    let config: Value = serde_json::from_slice(config)?;
    ensure(
        config["rootfs"]["diff_ids"] == *layers
            && config["config"]["User"] == "65532:65532"
            && config["config"]["Entrypoint"] == json!(["/server"]),
        "Runtime configuration changed",
    )?;
    let id = inspected["Id"].as_str().ok_or("Missing image identity")?;
    ensure(is_digest(id), "Nonimmutable daemon identity")?;
    Ok(id.into())
}
pub fn verify_release(root: &Path, image: &str, report: &Path) -> Result {
    ensure(
        regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$")?.is_match(image),
        "Invalid local reference",
    )?;
    let report = crate::grype::receipt(report, Utc::now())?;
    let inspected = inspect(root, image)?;
    let archive = tempfile::NamedTempFile::new()?;
    util::quiet(
        &mut util::cmd(
            "docker",
            &[
                "save",
                inspected["Id"].as_str().ok_or("Missing identity")?,
                "--output",
                archive.path().to_str().ok_or("Invalid path")?,
            ],
            root,
        ),
        180,
    )?;
    println!(
        "{}",
        verify_content(
            &report,
            &inspected,
            &saved_config(archive.path())?,
            Utc::now()
        )?
    );
    Ok(())
}
pub fn verify_elf(binary: &[u8]) -> Result {
    ensure(
        binary.len() >= 64 && &binary[..5] == b"\x7fELF\x02" && [1, 2].contains(&binary[5]),
        "Expected 64-bit ELF",
    )?;
    let little = binary[5] == 1;
    let u16_at = |p| {
        let b = <[u8; 2]>::try_from(&binary[p..p + 2]).expect("ELF field");
        if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    };
    let b: [u8; 8] = binary[32..40].try_into()?;
    let offset = if little {
        u64::from_le_bytes(b)
    } else {
        u64::from_be_bytes(b)
    };
    let size = u64::from(u16_at(54));
    let count = u64::from(u16_at(56));
    ensure(
        size >= 4
            && offset
                .checked_add(size * count)
                .is_some_and(|end| end <= binary.len() as u64),
        "Invalid ELF program headers",
    )?;
    for n in 0..count {
        let start = (offset + n * size) as usize;
        let b = binary[start..start + 4].try_into()?;
        let kind = if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        };
        ensure(kind != 3, "Dynamic ELF interpreter found")?;
    }
    Ok(())
}
pub fn verify_filesystem(path: &Path) -> Result {
    let mut archive = tar::Archive::new(util::bounded_file(path, 8 * 1024 * 1024 * 1024)?);
    let mut executables = Vec::new();
    let mut binary = None;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry
            .path()?
            .to_string_lossy()
            .trim_start_matches("./")
            .trim_start_matches('/')
            .to_string();
        ensure(
            ![
                "bin/sh",
                "bin/bash",
                "sbin/apk",
                "usr/bin/apt",
                "usr/bin/env",
            ]
            .contains(&path.as_str()),
            "Shell or package manager in runtime",
        )?;
        if entry.header().entry_type().is_file() && entry.header().mode()? & 0o111 != 0 {
            if [
                ".dockerenv",
                "dev/console",
                "etc/hostname",
                "etc/hosts",
                "etc/resolv.conf",
            ]
            .contains(&path.as_str())
            {
                let mut prefix = [0; 4];
                let n = entry.read(&mut prefix)?;
                ensure(
                    !(n >= 2 && &prefix[..2] == b"#!") && !(n == 4 && &prefix == b"\x7fELF"),
                    "Injected executable",
                )?;
            } else {
                executables.push(path.clone());
            }
        }
        if path == "server" {
            ensure(
                binary.is_none()
                    && entry.header().entry_type().is_file()
                    && entry.size() <= 128 * 1024 * 1024,
                "Invalid server binary",
            )?;
            let mut bytes = Vec::new();
            entry.take(128 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            binary = Some(bytes);
        }
    }
    ensure(executables == ["server"], "Unexpected runtime executable")?;
    verify_elf(&binary.ok_or("Missing server")?)
}
pub fn verify_image(root: &Path) -> Result {
    util::local_docker(root)?;
    let inspected = inspect(root, "obsidian-sync:local")?;
    ensure(
        inspected["Config"]["User"] == "65532:65532"
            && inspected["Config"]["Entrypoint"] == json!(["/server"]),
        "Runtime must be explicitly non-root",
    )?;
    let container = util::Container::new(root, "sync-image-check");
    util::quiet(
        &mut util::cmd(
            "docker",
            &[
                "create",
                "--name",
                &container.name,
                inspected["Id"].as_str().ok_or("Missing ID")?,
            ],
            root,
        ),
        30,
    )?;
    let archive = tempfile::NamedTempFile::new()?;
    util::run(
        util::cmd("docker", &["export", &container.name], root).stdout(archive.reopen()?),
        180,
    )?;
    verify_filesystem(archive.path())?;
    println!("Verified non-root, only /server executable, static ELF and no shell/package manager");
    Ok(())
}
