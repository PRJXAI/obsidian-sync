use crate::{Error, Result};
use serde::Deserialize;
use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
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
        if !self.metadata_dir.is_absolute()
            || self.max_blob_bytes == 0
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
