use async_trait::async_trait;
use obsidian_sync_server::{
    Error, Result,
    config::StorageConfig,
    db::Database,
    storage::{BlobInfo, BlobKey, BlobStorage, BlockingPool, Reader, Store},
    sync::{Engine, Mutation},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

struct LosePublicationResponse {
    inner: Store,
    once: Arc<AtomicBool>,
}
#[async_trait]
impl BlobStorage for LosePublicationResponse {
    async fn put(&self, info: BlobInfo, input: Reader) -> Result<()> {
        self.inner.put(info, input).await?;
        if self.once.swap(false, Ordering::SeqCst) {
            return Err(Error::Backend);
        }
        Ok(())
    }
    async fn get(&self, key: BlobKey) -> Result<Reader> {
        self.inner.get(key).await
    }
}
#[tokio::test]
async fn blob_published_metadata_not_committed_is_recoverable() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let pool = BlockingPool::new(2).unwrap();
    let db = Database::open(&root.join("metadata"), pool.clone())
        .await
        .unwrap();
    let vault = db.create_vault(8192).await.unwrap();
    let (_, token) = db.issue(vault, true).await.unwrap();
    let who = db.authenticate(&token).await.unwrap();
    let inner = Store::open(
        &StorageConfig::Filesystem {
            root: root.join("blobs"),
        },
        pool,
        100,
        30,
    )
    .await
    .unwrap();
    let store = Store::from_adapter(LosePublicationResponse {
        inner,
        once: Arc::new(AtomicBool::new(true)),
    });
    let engine = Engine::new(db.clone(), store.clone(), 2, 100, Duration::from_secs(30)).unwrap();
    let info = engine
        .reserve(&who, vault, 4, Sha256::digest(b"note").into(), "reserve")
        .await
        .unwrap();
    assert!(
        engine
            .upload(&who, info, Box::pin(std::io::Cursor::new(b"note")))
            .await
            .is_err()
    );
    let mutation = Mutation::Put {
        path: "x.md".into(),
        expected: 0,
        blob: info.key.object,
    };
    assert!(matches!(
        engine.mutate(&who, vault, "write", mutation.clone()).await,
        Err(Error::Conflict)
    ));
    drop(engine);
    drop(db);
    let db = Database::open(&root.join("metadata"), BlockingPool::new(2).unwrap())
        .await
        .unwrap();
    let engine = Engine::new(db, store, 2, 100, Duration::from_secs(30)).unwrap();
    assert_eq!(
        engine
            .reserve(&who, vault, 4, Sha256::digest(b"note").into(), "reserve")
            .await
            .unwrap(),
        info
    );
    engine
        .upload(&who, info, Box::pin(std::io::Cursor::new(b"note")))
        .await
        .unwrap();
    assert_eq!(
        engine.mutate(&who, vault, "write", mutation).await.unwrap(),
        1
    );
}
