//! Native GCS and Azure adapters, using maintained provider authentication and copy APIs.
use super::{BlobInfo, BlobKey, BlockingPool, Reader, copy_verified};
use crate::{Error, Result, config::StorageConfig};
use futures_util::TryStreamExt;
use object_store::{ObjectStore, ObjectStoreExt, buffered::BufWriter, path::Path};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio_util::io::StreamReader;

#[derive(Clone)]
pub struct Cloud {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
    max: u64,
}
impl Cloud {
    pub async fn open(config: &StorageConfig, max: u64, timeout: u64) -> Result<Self> {
        let options = object_store::ClientOptions::new()
            .with_allow_http(false)
            .with_connect_timeout(Duration::from_secs(5))
            .with_timeout(Duration::from_secs(timeout));
        let retry = object_store::RetryConfig {
            max_retries: 2,
            retry_timeout: Duration::from_secs(timeout),
            ..Default::default()
        };
        let pool = BlockingPool::new(1)?;
        let (inner, prefix): (Arc<dyn ObjectStore>, String) = match config {
            #[cfg(feature = "gcs")]
            StorageConfig::Gcs { bucket, prefix } => {
                let key = read_secret("GCS_SERVICE_ACCOUNT_FILE", 16384).await?;
                let bucket = bucket.clone();
                let store = pool
                    .run(move || {
                        object_store::gcp::GoogleCloudStorageBuilder::new()
                            .with_bucket_name(bucket)
                            .with_service_account_key(key)
                            .with_client_options(options)
                            .with_retry(retry)
                            .build()
                            .map_err(|_| Error::Backend)
                    })
                    .await?;
                (Arc::new(store), prefix.clone())
            }
            #[cfg(feature = "azure")]
            StorageConfig::Azure {
                account,
                container,
                prefix,
            } => {
                let token = read_secret("AZURE_SAS_TOKEN_FILE", 8192).await?;
                let pairs = parse_azure_sas(&token)?;
                let account = account.clone();
                let container = container.clone();
                let store = pool
                    .run(move || {
                        object_store::azure::MicrosoftAzureBuilder::new()
                            .with_account(account)
                            .with_container_name(container)
                            .with_sas_authorization(pairs)
                            .with_client_options(options)
                            .with_retry(retry)
                            .build()
                            .map_err(|_| Error::Backend)
                    })
                    .await?;
                (Arc::new(store), prefix.clone())
            }
            _ => return Err(Error::Invalid),
        };
        let store = Self { inner, prefix, max };
        let info = BlobInfo {
            key: BlobKey::new(uuid::Uuid::nil()),
            size: 1,
            digest: Sha256::digest(b"a").into(),
        };
        store
            .put(info, Box::pin(std::io::Cursor::new(b"a")))
            .await?;
        let other = BlobInfo {
            digest: Sha256::digest(b"b").into(),
            ..info
        };
        if !matches!(
            store.put(other, Box::pin(std::io::Cursor::new(b"b"))).await,
            Err(Error::Conflict)
        ) {
            return Err(Error::Backend);
        }
        let mut reader = store.get(info.key).await?;
        copy_verified(&mut reader, &mut tokio::io::sink(), info).await?;
        Ok(store)
    }
    fn path(&self, key: BlobKey) -> Path {
        Path::from(format!("{}/{}", self.prefix, key.path()))
    }
    pub async fn put(&self, info: BlobInfo, mut input: Reader) -> Result<()> {
        if info.size > self.max {
            return Err(Error::Limit);
        }
        let stage = Path::from(format!("{}/staging/{}", self.prefix, info.key.path()));
        let mut writer =
            BufWriter::with_capacity(self.inner.clone(), stage.clone(), 5 * 1024 * 1024)
                .with_max_concurrency(1);
        // The temporary object may be multipart; only the final conditional copy publishes.
        if let Err(e) = copy_verified(&mut input, &mut writer, info).await {
            let _ = writer.abort().await;
            let _ = self.inner.delete(&stage).await;
            return Err(e);
        }
        writer.shutdown().await?;
        let result = self
            .inner
            .copy_opts(
                &stage,
                &self.path(info.key),
                object_store::CopyOptions::new().with_mode(object_store::CopyMode::Create),
            )
            .await
            .map_err(map_error);
        // No final object is ever deleted. A failed cleanup leaves an unreferenced staging key.
        let _ = self.inner.delete(&stage).await;
        result
    }
    pub async fn get(&self, key: BlobKey) -> Result<Reader> {
        let result = self.inner.get(&self.path(key)).await.map_err(map_error)?;
        let stream = result
            .into_stream()
            .map_err(|_| std::io::Error::other("object read failed"));
        Ok(Box::pin(StreamReader::new(stream)))
    }
}
#[cfg(feature = "azure")]
fn parse_azure_sas(token: &str) -> Result<Vec<(String, String)>> {
    let pairs: Vec<_> =
        url::form_urlencoded::parse(token.trim().trim_start_matches('?').as_bytes())
            .into_owned()
            .collect();
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let mut seen = std::collections::HashSet::new();
    if pairs.iter().any(|(k, _)| !seen.insert(k))
        || get("sr") != Some("c")
        || get("spr") != Some("https")
        || get("sig").is_none_or(str::is_empty)
        || get("se").is_none_or(str::is_empty)
        || get("sp").is_none_or(|p| {
            !['r', 'c', 'w', 'd'].iter().all(|c| p.contains(*c))
                || !p.chars().all(|c| "rcwd".contains(c))
        })
    {
        return Err(Error::Invalid);
    }
    Ok(pairs)
}

async fn read_secret(variable: &str, limit: u64) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let path = std::env::var_os(variable).ok_or(Error::Invalid)?;
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).await?;
    if bytes.len() as u64 > limit {
        return Err(Error::Limit);
    }
    let value = String::from_utf8(bytes).map_err(|_| Error::Invalid)?;
    if value.trim().is_empty() {
        return Err(Error::Invalid);
    }
    Ok(value)
}

#[cfg(all(test, feature = "azure"))]
mod tests {
    use super::parse_azure_sas;
    #[test]
    fn azure_requires_https_expiring_container_scoped_minimal_sas() {
        let token = "sv=2025-01-05&sr=c&spr=https&sp=rcwd&se=2027-01-01T00%3A00%3A00Z&sig=fixture";
        assert!(parse_azure_sas(token).is_ok());
        for bad in [
            token.replace("sr=c", "sr=b"),
            token.replace("spr=https", "spr=https,http"),
            token.replace("sp=rcwd", "sp=rcwdl"),
            format!("{token}&sr=c"),
            token.replace("sig=fixture", "sig="),
        ] {
            assert!(parse_azure_sas(&bad).is_err());
        }
    }
}

fn map_error(e: object_store::Error) -> Error {
    match e {
        object_store::Error::AlreadyExists { .. } | object_store::Error::Precondition { .. } => {
            Error::Conflict
        }
        _ => Error::Backend,
    }
}
