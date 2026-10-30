//! Fixed CI image handoff, not a configurable build/deployment framework.
use crate::{Result, ensure, images, policy, util};
use std::{collections::BTreeMap, fs, io::Write, os::unix::fs::DirBuilderExt, path::Path};

const ARCHIVES: [(&str, &str); 2] = [
    ("runtime.tar", "obsidian-sync:local"),
    ("builder.tar", "obsidian-sync:builder"),
];

pub fn checksums(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    ensure(bytes.len() <= 1024, "Image checksum byte limit")?;
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(bytes)?.lines() {
        let (hash, name) = line.split_once("  ").ok_or("Invalid image checksums")?;
        ensure(
            images::is_digest(&format!("sha256:{hash}"))
                && ARCHIVES.iter().any(|(file, _)| *file == name)
                && values
                    .insert(name.into(), format!("sha256:{hash}"))
                    .is_none(),
            "Foreign/duplicate image checksum",
        )?;
    }
    ensure(values.len() == 2, "Both image checksums required")?;
    Ok(values)
}

pub fn build(root: &Path) -> Result {
    let revision = std::env::var("GITHUB_SHA")?;
    ensure(policy::is_revision(&revision), "Source revision required")?;
    util::local_docker(root)?;
    let work = root.join(".work/ci-images");
    fs::create_dir_all(root.join(".work"))?;
    fs::DirBuilder::new().mode(0o700).create(&work)?;
    for (phase, args, seconds) in [
        ("linux-tests", vec!["build", "--target", "tests", "."], 2400),
        (
            "builder",
            vec![
                "build",
                "--target",
                "build",
                "-t",
                "obsidian-sync:builder",
                ".",
            ],
            1200,
        ),
        (
            "runtime",
            vec![
                "build",
                "--build-arg",
                "SOURCE_REVISION",
                "-t",
                "obsidian-sync:local",
                ".",
            ],
            1200,
        ),
    ] {
        println!("CI image phase: {phase}");
        util::logged(
            util::cmd("docker", &args, root).env("SOURCE_REVISION", &revision),
            &work.join(format!("{phase}.private.log")),
            seconds,
        )?;
    }
    images::verify_image(root)?;
    let mut sums = String::new();
    for (file, image) in ARCHIVES {
        // Preserve the handoff's sole explicit tag (saving by bare ID drops it).
        // Subsequent jobs verify archive bytes/config/layers before using it.
        let inspected = images::inspect(root, image)?;
        let path = work.join(file);
        util::logged(
            &mut util::cmd(
                "docker",
                &[
                    "save",
                    image,
                    "--output",
                    path.to_str().ok_or("Invalid archive path")?,
                ],
                root,
            ),
            &work.join(format!("{file}.private.log")),
            180,
        )?;
        let material = images::archive_material(&inspected, &path)?;
        let digest = material["archive_digest"]
            .as_str()
            .ok_or("Archive hash required")?;
        sums.push_str(&format!(
            "{}  {file}\n",
            digest
                .strip_prefix("sha256:")
                .ok_or("Invalid archive hash")?
        ));
    }
    // The workflow uploads only these three allowlisted files, not private logs.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(work.join("SHA256SUMS"))?;
    file.write_all(sums.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

pub fn load(root: &Path, runtime_only: bool) -> Result {
    util::local_docker(root)?;
    let work = root.join(".work/ci-images");
    let sums = checksums(&util::read(&work.join("SHA256SUMS"), 1024)?)?;
    // Validate the entire handoff before asking Docker to mutate its image store.
    for (file, image) in ARCHIVES {
        let path = work.join(file);
        ensure(
            util::hash(&path)? == sums[file],
            "Image archive checksum mismatch",
        )?;
        images::saved_config(&path)?;
        let manifest = util::strict_json(&images::member(&path, "manifest.json", 1024 * 1024)?)?;
        ensure(
            manifest[0]["RepoTags"] == serde_json::json!([image]),
            "Unexpected archive tags",
        )?;
    }
    for (file, image) in ARCHIVES {
        if runtime_only && file == "builder.tar" {
            continue;
        }
        let path = work.join(file);
        util::output(
            &mut util::cmd(
                "docker",
                &[
                    "load",
                    "--input",
                    path.to_str().ok_or("Invalid archive path")?,
                ],
                root,
            ),
            180,
        )?;
        let material = images::archive_material(&images::inspect(root, image)?, &path)?;
        ensure(
            material["archive_digest"] == sums[file],
            "Loaded archive changed",
        )?;
    }
    Ok(())
}

pub fn install_deployment_tools(root: &Path) -> Result {
    ensure(
        std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true"),
        "CI-only tool installation",
    )?;
    let bin = root.join(".work/ci-tools/bin");
    fs::create_dir_all(bin.parent().ok_or("Missing tool directory")?)?;
    fs::DirBuilder::new().mode(0o700).create(&bin)?;
    util::logged(
        util::cmd(
            "go",
            &["install", "sigs.k8s.io/kustomize/kustomize/v5@v5.8.3"],
            root,
        )
        .env("GOBIN", &bin)
        .env("GOTOOLCHAIN", "go1.27.3")
        .env("GOWORK", "off"),
        &bin.parent().unwrap().join("kustomize.private.log"),
        900,
    )?;
    use std::os::unix::fs::OpenOptionsExt;
    let path = std::env::var("GITHUB_PATH")?;
    let mut file = fs::OpenOptions::new()
        .append(true)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32)
        .open(path)?;
    ensure(file.metadata()?.is_file(), "Regular CI path file required")?;
    writeln!(
        file,
        "{}",
        bin.to_str()
            .filter(|s| !s.contains(['\n', '\r']))
            .ok_or("Invalid tool path")?
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn image_checksums_reject_partial_duplicate_foreign_and_escaping_handoffs() {
        let good = format!(
            "{}  runtime.tar\n{}  builder.tar\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert_eq!(checksums(good.as_bytes()).unwrap().len(), 2);
        for bad in [
            String::new(),
            format!("{good}{good}"),
            good.replace("builder.tar", "../private"),
            good.replace("builder.tar", "other.tar"),
            good.replace("  ", " "),
            good.replace('a', "A"),
            good.lines().next().unwrap().into(),
            format!("{good}\n"),
        ] {
            assert!(checksums(bad.as_bytes()).is_err());
        }
    }
}
