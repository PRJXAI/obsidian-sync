use crate::{Result, ensure, util};
use regex::Regex;
use rustix::fs::{Mode, OFlags};
use serde_json::json;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Write,
    os::{fd::OwnedFd, unix::fs::MetadataExt},
    path::{Component, Path, PathBuf},
};

const FOLDERS: &[&str] = &[
    "src", "tests", "config", "deploy", ".github", ".agents", ".cargo", "scripts", "examples",
    "xtask",
];
const FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    ".env.example",
    "deny.toml",
    "AGENTS.md",
    "LICENSE",
];

pub fn fingerprints(root: &Path) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for relative in util::tracked(root)? {
        let name = relative.to_str().ok_or("Non-UTF8 source path")?;
        if !root.join(&relative).exists() {
            continue;
        }
        if FILES.contains(&name)
            || (name.starts_with("docker-compose") && name.ends_with(".yml"))
            || FOLDERS.iter().any(|folder| relative.starts_with(folder))
        {
            let file = util::regular_source(root, &relative)?;
            result.insert(
                name.into(),
                util::digest(&util::read(&file, util::JSON_LIMIT)?),
            );
        }
    }
    Ok(result)
}

fn markdown(root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = vec![
        root.join("README.md"),
        root.join("AGENTS.md"),
        root.join("llms.txt"),
    ];
    for item in walkdir::WalkDir::new(root.join("docs")).follow_links(false) {
        let item = item?;
        ensure(
            !item.file_type().is_symlink(),
            "Documentation symlink rejected",
        )?;
        if item.file_type().is_file() && item.path().extension().is_some_and(|x| x == "md") {
            paths.push(item.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}
fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => (),
            _ => result.push(part),
        }
    }
    result
}
pub fn links(path: &Path) -> Result<Vec<PathBuf>> {
    let expression = Regex::new(r"\[[^\]]*\]\(([^\s)#]+)(?:#[^)]*)?\)")?;
    let text = String::from_utf8(util::read(path, 4 * 1024 * 1024)?)?;
    Ok(expression
        .captures_iter(&text)
        .filter_map(|c| {
            let target = &c[1];
            (!target.contains("://") && !target.starts_with("mailto:") && !target.starts_with('#'))
                .then(|| normalize(&path.parent().expect("doc parent").join(target)))
        })
        .collect())
}
// Descriptor-relative no-follow traversal, not canonicalization alone. Only the
// scoped parent handle is used for publication/deletion after validation.
fn parent(root: &Path, relative: &Path, create: bool) -> Result<(OwnedFd, OsString)> {
    let parts = relative.components().collect::<Vec<_>>();
    ensure(
        parts.len() >= 2
            && parts[0].as_os_str() == "docs"
            && parts.iter().all(|x| matches!(x, Component::Normal(_)))
            && relative.extension().is_some_and(|x| x == "md"),
        "Only docs/*.md paths without traversal are permitted",
    )?;
    let mut fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    for part in &parts[..parts.len() - 1] {
        if create {
            match rustix::fs::mkdirat(&fd, part.as_os_str(), Mode::from_bits_truncate(0o755)) {
                Ok(()) => (),
                Err(rustix::io::Errno::EXIST) => (),
                Err(e) => return Err(e.into()),
            }
        }
        fd = rustix::fs::openat(
            &fd,
            part.as_os_str(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
    }
    Ok((fd, parts.last().expect("doc basename").as_os_str().into()))
}
pub fn create(root: &Path, relative: &Path, title: &str) -> Result {
    let (fd, name) = parent(root, relative, true)?;
    let file = rustix::fs::openat(
        fd,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o644),
    )?;
    let mut file = fs::File::from(file);
    writeln!(
        file,
        "# {title}\n\nStatus: draft. Add verified behavior, sources, limits and reproduction commands."
    )?;
    Ok(())
}
pub fn update(root: &Path, relative: &Path, source: &Path) -> Result {
    let content = util::read(source, 4 * 1024 * 1024)?;
    let (fd, name) = parent(root, relative, false)?;
    let file = rustix::fs::openat(
        fd,
        name,
        OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let mut file = fs::File::from(file);
    let info = file.metadata()?;
    ensure(
        info.is_file() && info.nlink() == 1,
        "Document must be an unlinked regular file",
    )?;
    file.set_len(0)?;
    file.write_all(&content)?;
    Ok(())
}
pub fn delete(root: &Path, relative: &Path, reason: &str, yes: bool) -> Result {
    ensure(
        yes && !reason.trim().is_empty(),
        "Deletion requires --yes and a reason",
    )?;
    let (fd, name) = parent(root, relative, false)?;
    let target = root.join(relative);
    for doc in markdown(root)? {
        ensure(
            doc == target || !links(&doc)?.contains(&target),
            "Remove inbound links before deleting",
        )?;
    }
    let object = format!("HEAD:{}", relative.to_str().ok_or("Invalid doc path")?);
    util::quiet(
        &mut util::cmd("git", &["cat-file", "-e", &object], root),
        30,
    )?;
    util::quiet(
        &mut util::cmd(
            "git",
            &[
                "diff",
                "--quiet",
                "HEAD",
                "--",
                relative.to_str().ok_or("Invalid doc path")?,
            ],
            root,
        ),
        30,
    )?;
    rustix::fs::unlinkat(fd, name, rustix::fs::AtFlags::empty())?;
    Ok(())
}
pub fn review(root: &Path, reason: &str) -> Result {
    ensure(
        !reason.trim().is_empty(),
        "A real review reason is required",
    )?;
    let sources = fingerprints(root)?
        .into_iter()
        .map(|(path, sha256)| json!({"path":path,"sha256":sha256}))
        .collect::<Vec<_>>();
    util::write_json(
        &root.join("docs/review.json"),
        &json!({"reason":reason,"sources":sources}),
    )
}
pub fn check(root: &Path) -> Result {
    let canonical = root.canonicalize()?;
    for path in markdown(root)? {
        util::regular_source(root, path.strip_prefix(root)?)?;
        ensure(
            !String::from_utf8(util::read(&path, 4 * 1024 * 1024)?)?.contains("Status: draft."),
            "Unreviewed draft",
        )?;
        for target in links(&path)? {
            ensure(
                target.canonicalize()?.starts_with(&canonical),
                "Broken or escaping documentation link",
            )?;
        }
    }
    let current = fingerprints(root)?;
    let recorded = util::json(&root.join("docs/review.json"))?;
    let previous = if let Some(map) = recorded["sources"].as_object() {
        map.iter()
            .map(|(k, v)| Ok((k.clone(), v.as_str().ok_or("Invalid fingerprint")?.into())))
            .collect::<Result<BTreeMap<String, String>>>()?
    } else {
        recorded["sources"]
            .as_array()
            .ok_or("Missing fingerprints")?
            .iter()
            .map(|v| {
                Ok((
                    v["path"].as_str().ok_or("Missing path")?.into(),
                    v["sha256"].as_str().ok_or("Missing digest")?.into(),
                ))
            })
            .collect::<Result<BTreeMap<String, String>>>()?
    };
    if current != previous {
        let changed = current
            .keys()
            .chain(previous.keys())
            .filter(|p| current.get(*p) != previous.get(*p))
            .collect::<std::collections::BTreeSet<_>>();
        eprintln!("Review changed sources before cargo xtask docs review: {changed:?}");
        return Err("Documentation source drift".into());
    }
    println!("Documentation links and reviewed source fingerprints are current");
    Ok(())
}
pub fn sync(root: &Path, check: bool) -> Result {
    let mut outputs = BTreeMap::new();
    outputs.insert(
        PathBuf::from("deploy/kustomize/base/config.toml"),
        util::read(&root.join("config/filesystem.toml"), 65536)?,
    );
    for provider in ["s3", "gcs", "azure"] {
        outputs.insert(
            PathBuf::from(format!("deploy/kustomize/overlays/{provider}/config.toml")),
            util::read(&root.join(format!("config/{provider}.toml")), 65536)?,
        );
    }
    let mut paths = util::tracked(root)?
        .into_iter()
        .filter(|p| root.join(p).is_file() && FOLDERS.iter().any(|folder| p.starts_with(folder)))
        .collect::<std::collections::BTreeSet<_>>();
    for path in &paths {
        util::regular_source(root, path)?;
    }
    paths.extend(outputs.keys().cloned());
    let mut map =
        "# Generated source map\n\nRun `cargo xtask sync-generated` after moving source files.\n\n"
            .to_string();
    for path in paths {
        map.push_str(&format!("- `{}`\n", path.display()));
    }
    outputs.insert(PathBuf::from("docs/source-map.md"), map.into_bytes());
    for (path, bytes) in outputs {
        let target = root.join(path);
        if check {
            ensure(
                util::read(&target, 4 * 1024 * 1024)? == bytes,
                "Stale generated configuration/source map",
            )?;
        } else {
            fs::create_dir_all(target.parent().expect("generated parent"))?;
            fs::write(target, bytes)?;
        }
    }
    Ok(())
}
