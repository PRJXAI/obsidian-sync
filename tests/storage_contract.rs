use obsidian_sync_server::{
    Error,
    config::StorageConfig,
    storage::{BlobInfo, BlobKey, BlockingPool, Store},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn contract(store: Store) {
    let vault = Uuid::new_v4();
    for size in [0, 1, 4096, 8 * 1024 * 1024] {
        let bytes = vec![42; size];
        let info = BlobInfo {
            key: BlobKey::new(vault),
            size: size as u64,
            digest: Sha256::digest(&bytes).into(),
        };
        store
            .put(info, Box::pin(std::io::Cursor::new(bytes.clone())))
            .await
            .unwrap();
        store.verify(info).await.unwrap();
        assert!(matches!(
            store.put(info, Box::pin(std::io::Cursor::new(bytes))).await,
            Err(Error::Conflict)
        ));
        store.verify(info).await.unwrap();
        assert!(
            store
                .get(BlobKey {
                    vault: Uuid::new_v4(),
                    object: info.key.object
                })
                .await
                .is_err()
        );
    }
    let info = BlobInfo {
        key: BlobKey::new(vault),
        size: 1,
        digest: Sha256::digest(b"a").into(),
    };
    let (a, b) = tokio::join!(
        store.put(info, Box::pin(std::io::Cursor::new(b"a"))),
        store.put(info, Box::pin(std::io::Cursor::new(b"a")))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    store.verify(info).await.unwrap();
    let wrong = BlobInfo {
        key: BlobKey::new(vault),
        size: 1,
        digest: [0; 32],
    };
    assert!(matches!(
        store.put(wrong, Box::pin(std::io::Cursor::new(b"a"))).await,
        Err(Error::Integrity)
    ));
    assert!(store.get(wrong.key).await.is_err());
    assert!(matches!(
        store
            .put(wrong, Box::pin(std::io::Cursor::new(b"ab")))
            .await,
        Err(Error::Limit)
    ));
    assert!(matches!(
        store
            .put(
                BlobInfo {
                    size: 32 * 1024 * 1024,
                    ..wrong
                },
                Box::pin(tokio::io::empty())
            )
            .await,
        Err(Error::Limit)
    ));
}
#[tokio::test]
async fn filesystem_contract() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("blobs");
    let config = StorageConfig::Filesystem { root };
    let store = Store::open(&config, BlockingPool::new(4).unwrap(), 16 * 1024 * 1024, 60)
        .await
        .unwrap();
    contract(store).await;
    // Open again: durability is not confined to an individual store instance.
    Store::open(&config, BlockingPool::new(4).unwrap(), 16 * 1024 * 1024, 60)
        .await
        .unwrap();
}
#[tokio::test]
async fn filesystem_rejects_symlink_roots_vaults_and_objects() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let external = root.join("outside");
    std::fs::create_dir(&external).unwrap();
    symlink(&external, root.join("alias")).unwrap();
    assert!(
        Store::open(
            &StorageConfig::Filesystem {
                root: root.join("alias")
            },
            BlockingPool::new(2).unwrap(),
            100,
            30
        )
        .await
        .is_err()
    );
    let blobs = root.join("blobs");
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: blobs.clone(),
        },
        BlockingPool::new(2).unwrap(),
        100,
        30,
    )
    .await
    .unwrap();
    let key = BlobKey::new(Uuid::new_v4());
    symlink(&external, blobs.join(key.vault.to_string())).unwrap();
    assert!(store.get(key).await.is_err());
    std::fs::remove_file(blobs.join(key.vault.to_string())).unwrap();
    std::fs::create_dir(blobs.join(key.vault.to_string())).unwrap();
    std::fs::write(external.join("secret"), b"secret").unwrap();
    symlink(external.join("secret"), blobs.join(key.path())).unwrap();
    assert!(store.get(key).await.is_err());
}
#[tokio::test]
async fn directory_swap_race_never_reads_outside_root() {
    use std::{
        os::unix::fs::symlink,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    use tokio::io::AsyncReadExt;
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let root = base.join("blobs");
    let outside = base.join("outside");
    std::fs::create_dir(&outside).unwrap();
    let store = Store::open(
        &StorageConfig::Filesystem { root: root.clone() },
        BlockingPool::new(2).unwrap(),
        100,
        30,
    )
    .await
    .unwrap();
    let info = BlobInfo {
        key: BlobKey::new(Uuid::new_v4()),
        size: 4,
        digest: Sha256::digest(b"note").into(),
    };
    store
        .put(info, Box::pin(std::io::Cursor::new(b"note")))
        .await
        .unwrap();
    std::fs::write(outside.join(info.key.object.to_string()), b"outside-secret").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let vault = root.join(info.key.vault.to_string());
    let held = root.join(".held");
    let attacker = std::thread::spawn(move || {
        while !done.load(Ordering::Relaxed) {
            if std::fs::rename(&vault, &held).is_ok() {
                let _ = symlink(&outside, &vault);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&vault);
                let _ = std::fs::remove_dir(&vault);
                let _ = std::fs::rename(&held, &vault);
            }
            std::thread::yield_now();
        }
    });
    let mut escaped = false;
    for _ in 0..200 {
        if let Ok(reader) = store.get(info.key).await {
            let mut bytes = Vec::new();
            if reader.take(32).read_to_end(&mut bytes).await.is_ok() && bytes != b"note" {
                escaped = true;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    assert!(!escaped, "read escaped through a swapped directory");
}

#[cfg(feature = "s3")]
#[tokio::test]
#[ignore = "requires real S3-compatible service; scripts/test-s3.sh"]
async fn s3_contract() {
    if std::env::var("SYNC_S3_CREATE_BUCKET").as_deref() == Ok("yes") {
        use rusty_s3::S3Action;
        let file = std::env::var("SYNC_S3_TEST_CONFIG").unwrap();
        let config = obsidian_sync_server::config::Config::load(std::path::Path::new(&file))
            .await
            .unwrap();
        let StorageConfig::S3 {
            endpoint,
            region,
            bucket,
            ..
        } = config.storage
        else {
            panic!("S3 config required")
        };
        assert!(
            endpoint.starts_with("http://127.0.0.1:"),
            "bucket creation is disposable loopback-only"
        );
        let access = tokio::fs::read_to_string(std::env::var("S3_ACCESS_KEY_FILE").unwrap())
            .await
            .unwrap();
        let secret = tokio::fs::read_to_string(std::env::var("S3_SECRET_KEY_FILE").unwrap())
            .await
            .unwrap();
        let credentials = rusty_s3::Credentials::new(access, secret);
        let bucket = rusty_s3::Bucket::new(
            endpoint.parse().unwrap(),
            rusty_s3::UrlStyle::Path,
            bucket,
            region,
        )
        .unwrap();
        let url = bucket
            .create_bucket(&credentials)
            .sign(std::time::Duration::from_secs(60));
        let response = reqwest::Client::new().put(url).send().await.unwrap();
        assert!(
            response.status().is_success(),
            "bucket setup failed: {}",
            response.status()
        );
    }
    external("SYNC_S3_TEST_CONFIG").await;
}
#[cfg(feature = "gcs")]
#[tokio::test]
#[ignore = "requires disposable GCS bucket and credentials"]
async fn gcs_contract() {
    external("SYNC_GCS_TEST_CONFIG").await;
}
#[cfg(feature = "azure")]
#[tokio::test]
#[ignore = "requires disposable Azure container and credentials"]
async fn azure_contract() {
    external("SYNC_AZURE_TEST_CONFIG").await;
}
#[cfg(any(feature = "s3", feature = "gcs", feature = "azure"))]
async fn external(variable: &str) {
    let file = std::env::var(variable).expect("explicit disposable test config required");
    let config = obsidian_sync_server::config::Config::load(std::path::Path::new(&file))
        .await
        .unwrap();
    let store = Store::open(
        &config.storage,
        BlockingPool::new(4).unwrap(),
        16 * 1024 * 1024,
        60,
    )
    .await
    .unwrap();
    contract(store).await;
}
