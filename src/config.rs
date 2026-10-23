use crate::{Error, Result};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    #[serde(default)]
    pub http: HttpConfig,
    pub metadata_dir: PathBuf,
    pub storage: StorageConfig,
    pub max_blob_bytes: u64,
    pub vault_quota_bytes: u64,
    pub max_inflight: usize,
    pub operation_timeout_secs: u64,
    pub job_quota_per_vault: u32,
    pub job_max_attempts: u32,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StorageConfig {
    Filesystem {
        root: PathBuf,
    },
    Gcs {
        bucket: String,
        prefix: String,
    },
    Azure {
        account: String,
        container: String,
        prefix: String,
    },
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
        prefix: String,
        path_style: bool,
        #[serde(default)]
        allow_insecure_loopback: bool,
    },
}

fn validate_cloud(name: &str, prefix: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 222
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b))
        || prefix.is_empty()
        || prefix.len() > 128
        || !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub allowed_origins: Vec<String>,
    pub max_request_bytes: usize,
    pub max_document_bytes: usize,
    pub max_response_bytes: usize,
    pub max_batch_docs: usize,
    pub max_requests: usize,
    pub requests_per_minute: u32,
    pub burst: u32,
    pub longpoll_seconds: u64,
}
impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            max_request_bytes: 16 * 1024 * 1024,
            max_document_bytes: 1024 * 1024,
            max_response_bytes: 16 * 1024 * 1024,
            max_batch_docs: 128,
            max_requests: 8,
            requests_per_minute: 6000,
            burst: 256,
            longpoll_seconds: 20,
        }
    }
}
impl HttpConfig {
    fn validate(&self) -> Result<()> {
        if !(4096..=32 * 1024 * 1024).contains(&self.max_request_bytes)
            || !(4096..=4 * 1024 * 1024).contains(&self.max_document_bytes)
            || self.max_document_bytes > self.max_request_bytes
            || !(4096..=32 * 1024 * 1024).contains(&self.max_response_bytes)
            || self.max_response_bytes < self.max_document_bytes
            || !(1..=256).contains(&self.max_batch_docs)
            || !(2..=16).contains(&self.max_requests)
            || self.max_requests * self.max_request_bytes > 256 * 1024 * 1024
            || !(1..=60000).contains(&self.requests_per_minute)
            || !(1..=1024).contains(&self.burst)
            || !(1..=30).contains(&self.longpoll_seconds)
            || self.allowed_origins.len() > 16
        {
            return Err(Error::Invalid);
        }
        for origin in &self.allowed_origins {
            if origin.len() > 256 || origin.contains(['*', '\r', '\n', '@', '#', '?']) {
                return Err(Error::Invalid);
            }
            let uri: axum::http::Uri = origin.parse().map_err(|_| Error::Invalid)?;
            if uri.authority().is_none()
                || !matches!(
                    uri.scheme_str(),
                    Some("https" | "app" | "capacitor" | "http")
                )
                || uri.path() != "/"
            {
                return Err(Error::Invalid);
            }
            if uri.scheme_str() == Some("http")
                && !matches!(uri.host(), Some("localhost" | "127.0.0.1"))
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }
}

impl Config {
    pub async fn load(path: &std::path::Path) -> Result<Self> {
        use tokio::io::AsyncReadExt;
        let file = tokio::fs::File::open(path).await?;
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1).read_to_end(&mut bytes).await?;
        if bytes.len() > 64 * 1024 {
            return Err(Error::Limit);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| Error::Invalid)?;
        let config: Self = toml::from_str(text).map_err(|_| Error::Invalid)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        self.http.validate()?;
        if !self.metadata_dir.is_absolute()
            || self.max_blob_bytes == 0
            || self.http.max_document_bytes as u64 > self.max_blob_bytes
            || self.max_blob_bytes > 1024 * 1024 * 1024
            || self.vault_quota_bytes < self.max_blob_bytes.max(4096)
            || self.vault_quota_bytes > i64::MAX as u64
            || !(1..=64).contains(&self.max_inflight)
            || !(1..=3600).contains(&self.operation_timeout_secs)
            || !(1..=1000).contains(&self.job_quota_per_vault)
            || !(1..=10).contains(&self.job_max_attempts)
        {
            return Err(Error::Invalid);
        }
        match &self.storage {
            StorageConfig::Filesystem { root } if !root.is_absolute() => Err(Error::Invalid),
            StorageConfig::S3 {
                endpoint,
                region,
                bucket,
                prefix,
                ..
            } => {
                if endpoint.len() > 2048
                    || region.is_empty()
                    || bucket.is_empty()
                    || prefix.is_empty()
                    || prefix.len() > 128
                    || !prefix
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err(Error::Invalid);
                }
                Ok(())
            }
            StorageConfig::Gcs { bucket, prefix } => validate_cloud(bucket, prefix),
            StorageConfig::Azure {
                account,
                container,
                prefix,
            } => {
                if account.is_empty()
                    || !account
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
                {
                    return Err(Error::Invalid);
                }
                validate_cloud(container, prefix)
            }
            _ => Ok(()),
        }
    }
}
