//! Immutable, vault-scoped blobs. No client-controlled filesystem or S3 keys.
use crate::{Error, Result, config::StorageConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::Path, pin::Pin, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
};
use uuid::Uuid;

#[cfg(any(feature = "gcs", feature = "azure"))]
pub mod cloud;
pub mod filesystem;
#[cfg(feature = "s3")]
pub mod s3;

pub type Reader = Pin<Box<dyn AsyncRead + Send>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlobKey {
    pub vault: Uuid,
    pub object: Uuid,
}
impl BlobKey {
    pub fn new(vault: Uuid) -> Self {
        Self {
            vault,
            object: Uuid::new_v4(),
        }
    }
    pub fn path(&self) -> String {
        format!("{}/{}", self.vault, self.object)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobInfo {
    pub key: BlobKey,
    pub size: u64,
    pub digest: [u8; 32],
}

/// All adapters have identical create-only, streaming and durability semantics.
/// Implementations receive server-generated keys, never client paths or endpoints.
#[async_trait::async_trait]
pub trait BlobStorage: Send + Sync {
    async fn put(&self, info: BlobInfo, input: Reader) -> Result<()>;
    async fn get(&self, key: BlobKey) -> Result<Reader>;
}

#[derive(Clone)]
pub struct Store(Arc<dyn BlobStorage>);
impl Store {
    pub fn from_adapter(adapter: impl BlobStorage + 'static) -> Self {
        Self(Arc::new(adapter))
    }
    pub async fn open(
        config: &StorageConfig,
        pool: BlockingPool,
        max: u64,
        timeout: u64,
    ) -> Result<Self> {
        let _ = timeout;
        match config {
            StorageConfig::Filesystem { root } => Ok(Self::from_adapter(
                filesystem::Filesystem::open(root, pool, max).await?,
            )),
            #[cfg(feature = "s3")]
            StorageConfig::S3 { .. } => Ok(Self::from_adapter(
                s3::S3::open(config, max, timeout).await?,
            )),
            #[cfg(not(feature = "s3"))]
            StorageConfig::S3 { .. } => Err(Error::Invalid),
            #[cfg(any(feature = "gcs", feature = "azure"))]
            StorageConfig::Gcs { .. } | StorageConfig::Azure { .. } => Ok(Self::from_adapter(
                cloud::Cloud::open(config, max, timeout).await?,
            )),
            #[cfg(not(any(feature = "gcs", feature = "azure")))]
            StorageConfig::Gcs { .. } | StorageConfig::Azure { .. } => Err(Error::Invalid),
        }
    }
    pub async fn put(&self, info: BlobInfo, input: Reader) -> Result<()> {
        self.0.put(info, input).await
    }
    pub async fn get(&self, key: BlobKey) -> Result<Reader> {
        self.0.get(key).await
    }
    pub async fn verify(&self, info: BlobInfo) -> Result<()> {
        let mut input = self.get(info.key).await?;
        let mut sink = tokio::io::sink();
        copy_verified(&mut input, &mut sink, info).await
    }
}

macro_rules! adapter {
    ($kind:ty) => {
        #[async_trait::async_trait]
        impl BlobStorage for $kind {
            async fn put(&self, info: BlobInfo, input: Reader) -> Result<()> {
                <$kind>::put(self, info, input).await
            }
            async fn get(&self, key: BlobKey) -> Result<Reader> {
                <$kind>::get(self, key).await
            }
        }
    };
}
adapter!(filesystem::Filesystem);
#[cfg(feature = "s3")]
adapter!(s3::S3);
#[cfg(any(feature = "gcs", feature = "azure"))]
adapter!(cloud::Cloud);

/// Bounds all first-party blocking filesystem/SQLite tasks, including canceled callers.
#[derive(Clone)]
pub struct BlockingPool(Arc<Semaphore>);
impl BlockingPool {
    pub fn new(size: usize) -> Result<Self> {
        if !(1..=64).contains(&size) {
            return Err(Error::Invalid);
        }
        Ok(Self(Arc::new(Semaphore::new(size))))
    }
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let permit = self
            .0
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Limit)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await?
    }
}

/// 64 KiB memory bound independent of attachment size. SHA work is bounded per yield.
pub async fn copy_verified<R, W>(input: &mut R, output: &mut W, info: BlobInfo) -> Result<()>
where
    R: AsyncRead + Unpin + ?Sized,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Keep nested transport futures small; a stack array multiplies across async frames.
    let mut buffer = vec![0_u8; 65536];
    let mut size = 0_u64;
    let mut hash = Sha256::new();
    loop {
        let n = input.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        size = size.checked_add(n as u64).ok_or(Error::Limit)?;
        if size > info.size {
            return Err(Error::Limit);
        }
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n]).await?;
        tokio::task::yield_now().await;
    }
    if size != info.size || <[u8; 32]>::from(hash.finalize()) != info.digest {
        return Err(Error::Integrity);
    }
    output.flush().await?;
    Ok(())
}

/// Walk from / using no-follow dirfds; even swapped symlinks cannot redirect access.
/// Backend roots and their parents must not be writable by untrusted OS identities.
pub fn private_root(path: &Path) -> Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::os::unix::fs::PermissionsExt;
    if !path.is_absolute() {
        return Err(Error::Invalid);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut dir = std::fs::File::from(open("/", flags, Mode::empty())?);
    for part in path.components().skip(1) {
        let std::path::Component::Normal(name) = part else {
            return Err(Error::Invalid);
        };
        match mkdirat(&dir, name, Mode::from_bits_truncate(0o700)) {
            Ok(()) => dir.sync_all()?,
            Err(rustix::io::Errno::EXIST) => (),
            Err(e) => return Err(e.into()),
        }
        dir = std::fs::File::from(openat(&dir, name, flags, Mode::empty())?);
    }
    if dir.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(Error::Invalid);
    }
    Ok(dir)
}
