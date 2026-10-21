use super::{BlobInfo, BlobKey, BlockingPool, Reader, copy_verified};
use crate::{Error, Result, config::StorageConfig};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncSeekExt;
use tokio_util::io::{ReaderStream, StreamReader};

#[derive(Clone)]
pub struct S3 {
    bucket: Arc<Bucket>,
    credentials: Arc<Credentials>,
    client: reqwest::Client,
    prefix: String,
    max: u64,
    pool: BlockingPool,
}
impl S3 {
    pub async fn open(config: &StorageConfig, max: u64, timeout: u64) -> Result<Self> {
        let StorageConfig::S3 {
            endpoint,
            region,
            bucket,
            prefix,
            path_style,
            allow_insecure_loopback,
        } = config
        else {
            return Err(Error::Invalid);
        };
        let endpoint: reqwest::Url = endpoint.parse().map_err(|_| Error::Invalid)?;
        let local = endpoint
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|a| a.is_loopback());
        if (endpoint.scheme() != "https"
            && !(endpoint.scheme() == "http" && *allow_insecure_loopback && local))
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
            || prefix.is_empty()
            || !prefix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Invalid);
        }
        let access = read_secret("S3_ACCESS_KEY_FILE").await?;
        let secret = read_secret("S3_SECRET_KEY_FILE").await?;
        let bucket = Bucket::new(
            endpoint,
            if *path_style {
                UrlStyle::Path
            } else {
                UrlStyle::VirtualHost
            },
            bucket.clone(),
            region.clone(),
        )
        .map_err(|_| Error::Invalid)?;
        let client = reqwest::Client::builder()
            .https_only(!*allow_insecure_loopback)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(timeout))
            .pool_max_idle_per_host(4)
            .no_proxy()
            .build()
            .map_err(|_| Error::Backend)?;
        let store = Self {
            bucket: Arc::new(bucket),
            credentials: Arc::new(Credentials::new(access, secret)),
            client,
            prefix: prefix.clone(),
            max,
            pool: BlockingPool::new(2)?,
        };
        // Probe both create and rejection of overwrite, then verify the original survived.
        let key = BlobKey::new(uuid::Uuid::nil());
        let info = BlobInfo {
            key,
            size: 1,
            digest: sha2::Sha256::digest(b"a").into(),
        };
        store
            .put(info, Box::pin(std::io::Cursor::new(b"a")))
            .await?;
        let other = BlobInfo {
            digest: sha2::Sha256::digest(b"b").into(),
            ..info
        };
        if !matches!(
            store.put(other, Box::pin(std::io::Cursor::new(b"b"))).await,
            Err(Error::Conflict)
        ) {
            return Err(Error::Backend);
        }
        let mut reader = store.get(key).await?;
        copy_verified(&mut reader, &mut tokio::io::sink(), info).await?;
        // Probe blobs are tiny and retained; requires no DeleteObject permission.
        Ok(store)
    }
    fn key(&self, key: BlobKey) -> String {
        format!("{}/{}", self.prefix, key.path())
    }
    pub async fn put(&self, info: BlobInfo, mut input: Reader) -> Result<()> {
        if info.size > self.max {
            return Err(Error::Limit);
        }
        // Spool to an anonymous local file: streaming, verified before any S3 publication.
        let file = self.pool.run(|| Ok(tempfile::tempfile()?)).await?;
        let mut file = tokio::fs::File::from_std(file);
        copy_verified(&mut input, &mut file, info).await?;
        file.rewind().await?;
        let key = self.key(info.key);
        let mut action = self.bucket.put_object(Some(&self.credentials), &key);
        action.headers_mut().insert("if-none-match", "*");
        let url = action.sign(Duration::from_secs(3600));
        let response = self
            .client
            .put(url)
            .header("if-none-match", "*")
            .header(reqwest::header::CONTENT_LENGTH, info.size)
            .body(reqwest::Body::wrap_stream(ReaderStream::with_capacity(
                file, 65536,
            )))
            .send()
            .await
            .map_err(|_| Error::Backend)?;
        if response.status() == reqwest::StatusCode::PRECONDITION_FAILED {
            return Err(Error::Conflict);
        }
        if !response.status().is_success() {
            return Err(Error::Backend);
        }
        Ok(())
    }
    pub async fn get(&self, key: BlobKey) -> Result<Reader> {
        use futures_util::TryStreamExt;
        let key = self.key(key);
        let url = self
            .bucket
            .get_object(Some(&self.credentials), &key)
            .sign(Duration::from_secs(3600));
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| Error::Backend)?;
        if !response.status().is_success() {
            return Err(Error::Backend);
        }
        let stream = response
            .bytes_stream()
            .map_err(|_| std::io::Error::other("object read failed"));
        Ok(Box::pin(StreamReader::new(stream)))
    }
}
use sha2::Digest;

async fn read_secret(variable: &str) -> Result<String> {
    let path = std::env::var_os(variable).ok_or(Error::Invalid)?;
    let mut file = tokio::fs::File::open(path).await?;
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    (&mut file).take(8193).read_to_end(&mut bytes).await?;
    if bytes.len() > 8192 {
        return Err(Error::Invalid);
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| Error::Invalid)?
        .trim()
        .to_owned();
    if value.is_empty() {
        return Err(Error::Invalid);
    }
    Ok(value)
}
