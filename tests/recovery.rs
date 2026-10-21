use obsidian_sync_server::{
    Error, Result,
    config::StorageConfig,
    db::Database,
    jobs::Queue,
    storage::{BlobInfo, BlobKey, BlockingPool, Store},
    sync::{Engine, Mutation},
};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{io::AsyncWriteExt, sync::watch};
use uuid::Uuid;

#[tokio::test]
async fn canceled_staging_is_bounded_and_recovered_on_restart() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("blobs");
    let config = StorageConfig::Filesystem { root: root.clone() };
    let pool = BlockingPool::new(2).unwrap();
    let store = Store::open(&config, pool.clone(), 100, 30).await.unwrap();
    let info = BlobInfo {
        key: BlobKey::new(Uuid::new_v4()),
        size: 4,
        digest: Sha256::digest(b"note").into(),
    };
    let (mut writer, reader) = tokio::io::duplex(64);
    writer.write_all(b"n").await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            store.put(info, Box::pin(reader))
        )
        .await
        .is_err()
    );
    assert!(store.get(info.key).await.is_err());
    assert!(matches!(
        store
            .put(info, Box::pin(std::io::Cursor::new(b"note")))
            .await,
        Err(Error::Backend)
    ));
    let stage = root
        .join(info.key.vault.to_string())
        .join(format!(".stage-{}", info.key.object));
    assert!(stage.exists());
    drop(store);
    drop(writer);
    let restarted = Store::open(&config, pool, 100, 30).await.unwrap();
    assert!(!stage.exists());
    restarted
        .put(info, Box::pin(std::io::Cursor::new(b"note")))
        .await
        .unwrap();
    restarted.verify(info).await.unwrap();
}
#[tokio::test]
async fn bounded_worker_completes_and_shuts_down() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let pool = BlockingPool::new(2)?;
    let db = Database::open(&root.join("metadata"), pool.clone()).await?;
    let vault = db.create_vault(8192).await?;
    let (_, token) = db.issue(vault, true).await?;
    let who = db.authenticate(&token).await?;
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: root.join("blobs"),
        },
        pool,
        100,
        30,
    )
    .await?;
    let engine = Engine::new(db.clone(), store.clone(), 2, 100, Duration::from_secs(30))?;
    let info = engine
        .reserve(&who, vault, 4, Sha256::digest(b"note").into(), "upload")
        .await?;
    engine
        .upload(&who, info, Box::pin(std::io::Cursor::new(b"note")))
        .await?;
    let queue = Queue::new(db.clone(), 10, 2)?;
    let id = queue.enqueue(&who, vault, "job").await?;
    let (tx, rx) = watch::channel(false);
    let worker = tokio::spawn(queue.clone().worker(store, Duration::from_secs(30), rx));
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if queue.status(&who, id).await.unwrap().state == "done" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // A newer note modification survives job completion: jobs never write heads.
    engine
        .mutate(
            &who,
            vault,
            "write",
            Mutation::Put {
                path: "x.md".into(),
                expected: 0,
                blob: info.key.object,
            },
        )
        .await?;
    tx.send(true).unwrap();
    worker.await??;
    assert_eq!(engine.changes(&who, vault, 0, 100).await?.high_water, 1);
    Ok(())
}
#[tokio::test]
async fn revision_budget_rejects_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let pool = BlockingPool::new(2).unwrap();
    let db = Database::open(&root.join("metadata"), pool.clone())
        .await
        .unwrap();
    let vault = db.create_vault(8192).await.unwrap();
    let (_, token) = db.issue(vault, true).await.unwrap();
    let who = db.authenticate(&token).await.unwrap();
    db.run(move |c| {
        c.execute(
            "UPDATE vaults SET revision=100000 WHERE id=?1",
            [vault.to_string()],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: root.join("blobs"),
        },
        pool,
        100,
        30,
    )
    .await
    .unwrap();
    let engine = Engine::new(db, store, 2, 100, Duration::from_secs(30)).unwrap();
    assert!(matches!(
        engine
            .mutate(
                &who,
                vault,
                "delete",
                Mutation::Delete {
                    path: "x".into(),
                    expected: 0
                }
            )
            .await,
        Err(Error::Limit)
    ));
    let page = engine.changes(&who, vault, 0, 100).await.unwrap();
    assert!(page.changes.is_empty());
    assert_eq!(page.high_water, 100000);
}
