use super::{BlobInfo, BlobKey, BlockingPool, Reader, copy_verified, private_root};
use crate::{Error, Result};
use rustix::fs::{AtFlags, Mode, OFlags, linkat, mkdirat, openat, unlinkat};
use std::{fs::File, path::Path, sync::Arc};

// Must run only while holding the installation's exclusive metadata writer lock.
fn recover_staging(root: &File) -> Result<()> {
    for entry in rustix::fs::Dir::read_from(root)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().to_str() else {
            return Err(Error::Integrity);
        };
        if uuid::Uuid::parse_str(name).is_err() {
            continue;
        }
        let dir = File::from(openat(
            root,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        for child in rustix::fs::Dir::read_from(&dir)? {
            let child = child?;
            let Ok(name) = child.file_name().to_str() else {
                return Err(Error::Integrity);
            };
            if name
                .strip_prefix(".stage-")
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
            {
                unlinkat(&dir, name, AtFlags::empty())?;
            }
        }
        dir.sync_all()?;
    }
    Ok(())
}

// A visible object after an interrupted publication may not yet be durable.
// Duplicate-write recovery must synchronize it, not merely read its bytes.
fn sync_existing(dir: &File, name: &str) -> Result<bool> {
    let file = match openat(
        dir,
        name,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::NOENT) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    if !file.metadata()?.is_file() {
        return Err(Error::Integrity);
    }
    file.sync_all()?;
    dir.sync_all()?;
    Ok(true)
}

#[derive(Clone)]
pub struct Filesystem {
    root: Arc<File>,
    pool: BlockingPool,
    max: u64,
}
impl Filesystem {
    pub async fn open(path: &Path, pool: BlockingPool, max: u64) -> Result<Self> {
        let path = path.to_owned();
        let root = pool
            .run(move || {
                let root = private_root(&path)?;
                recover_staging(&root)?;
                Ok(root)
            })
            .await?;
        Ok(Self {
            root: Arc::new(root),
            pool,
            max,
        })
    }
    async fn vault(&self, vault: uuid::Uuid) -> Result<File> {
        let root = self.root.clone();
        self.pool
            .run(move || {
                let name = vault.to_string();
                match mkdirat(&*root, &name, Mode::from_bits_truncate(0o700)) {
                    Ok(()) => root.sync_all()?,
                    Err(rustix::io::Errno::EXIST) => (),
                    Err(e) => return Err(e.into()),
                }
                Ok(File::from(openat(
                    &*root,
                    &name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )?))
            })
            .await
    }
    pub async fn put(&self, info: BlobInfo, mut input: Reader) -> Result<()> {
        if info.size > self.max {
            return Err(Error::Limit);
        }
        let dir = Arc::new(self.vault(info.key.vault).await?);
        let d = dir.clone();
        let object = info.key.object.to_string();
        if self.pool.run(move || sync_existing(&d, &object)).await? {
            return Err(Error::Conflict);
        }
        let stage = format!(".stage-{}", info.key.object);
        let d = dir.clone();
        let name = stage.clone();
        let file = self
            .pool
            .run(move || {
                Ok(File::from(
                    openat(
                        &*d,
                        name,
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_bits_truncate(0o600),
                    )
                    .map_err(|e| {
                        if e == rustix::io::Errno::EXIST {
                            // Another upload owns staging, not a durable final object.
                            Error::Backend
                        } else {
                            e.into()
                        }
                    })?,
                ))
            })
            .await?;
        let mut file = tokio::fs::File::from_std(file);
        let result = copy_verified(&mut input, &mut file, info).await;
        if result.is_ok() {
            file.sync_all().await?;
        }
        drop(file);
        let name = info.key.object.to_string();
        self.pool
            .run(move || {
                if result.is_ok() {
                    // Hard-link publication is atomic no-clobber; no unsafe rename fallback.
                    let publication = linkat(&*dir, &stage, &*dir, &name, AtFlags::empty());
                    if let Err(e) = publication {
                        let _ = unlinkat(&*dir, &stage, AtFlags::empty());
                        return if e == rustix::io::Errno::EXIST {
                            if !sync_existing(&dir, &name)? {
                                return Err(Error::Integrity);
                            }
                            Err(Error::Conflict)
                        } else {
                            Err(e.into())
                        };
                    }
                }
                unlinkat(&*dir, &stage, AtFlags::empty())?;
                dir.sync_all()?;
                result
            })
            .await
    }
    pub async fn get(&self, key: BlobKey) -> Result<Reader> {
        let dir = self.vault(key.vault).await?;
        let file = self
            .pool
            .run(move || {
                let f = File::from(openat(
                    &dir,
                    key.object.to_string(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )?);
                if !f.metadata()?.is_file() {
                    return Err(Error::Invalid);
                }
                Ok(f)
            })
            .await?;
        Ok(Box::pin(tokio::fs::File::from_std(file)))
    }
}
