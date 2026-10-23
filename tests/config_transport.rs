use obsidian_sync_server::{Error, config::Config};

#[tokio::test]
async fn strict_configuration_and_bounded_input() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("config.toml");
    let valid = include_str!("../config/filesystem.toml");
    tokio::fs::write(&path, valid).await.unwrap();
    Config::load(&path).await.unwrap();
    for invalid in [
        valid.replace("max_inflight = 4", "max_inflight = 0"),
        valid.replace("268435456", "999999999999"),
        valid.replace("/data/metadata", "relative"),
        valid.replace("listen =", "unknown_key ="),
    ] {
        tokio::fs::write(&path, invalid).await.unwrap();
        assert!(matches!(Config::load(&path).await, Err(Error::Invalid)));
    }
    tokio::fs::write(&path, vec![b' '; 65537]).await.unwrap();
    assert!(matches!(Config::load(&path).await, Err(Error::Limit)));
}
#[cfg(feature = "s3")]
#[tokio::test]
async fn object_store_endpoints_cannot_disable_remote_tls_or_embed_urls() {
    use obsidian_sync_server::{
        config::StorageConfig,
        storage::{BlockingPool, Store},
    };
    for endpoint in [
        "http://169.254.169.254",
        "http://s3.example.invalid",
        "https://user:secret@s3.example.invalid",
        "https://s3.example.invalid/proxy",
        "https://s3.example.invalid/?redirect=elsewhere",
    ] {
        let config = StorageConfig::S3 {
            endpoint: endpoint.into(),
            region: "us-east-1".into(),
            bucket: "private-test".into(),
            prefix: "test".into(),
            path_style: true,
            allow_insecure_loopback: true,
        };
        assert!(matches!(
            Store::open(&config, BlockingPool::new(1).unwrap(), 100, 1).await,
            Err(Error::Invalid)
        ));
    }
}

#[test]
fn http_limits_and_cors_are_validated() {
    let config: Config = toml::from_str(include_str!("../config/filesystem.toml")).unwrap();
    for origin in [
        "*",
        "null",
        "https://user:password@example.invalid",
        "https://example.invalid/path",
        "http://remote.invalid",
    ] {
        let mut invalid = config.clone();
        invalid.http.allowed_origins = vec![origin.into()];
        assert!(invalid.validate().is_err());
    }
    let mut invalid = config.clone();
    invalid.http.max_requests = 0;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.http.max_document_bytes = 8 * 1024 * 1024;
    assert!(invalid.validate().is_err());
    let mut invalid = config.clone();
    invalid.http.longpoll_seconds = 31;
    assert!(invalid.validate().is_err());
    let mut invalid = config;
    invalid.http.burst = 0;
    assert!(invalid.validate().is_err());
}
