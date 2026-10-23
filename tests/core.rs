use obsidian_sync_server::{
    Error,
    auth::Identity,
    config::StorageConfig,
    db::Database,
    jobs::Queue,
    storage::{BlobInfo, BlockingPool, Store},
    sync::{Engine, Mutation, validate_path},
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};
use tempfile::TempDir;
use uuid::Uuid;

struct Fixture {
    _temp: TempDir,
    root: PathBuf,
    db: Database,
    engine: Engine,
    vault: Uuid,
    who: Identity,
}
impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let pool = BlockingPool::new(4).unwrap();
        let db = Database::open(&root.join("metadata"), pool.clone())
            .await
            .unwrap();
        let store = Store::open(
            &StorageConfig::Filesystem {
                root: root.join("blobs"),
            },
            pool,
            1024 * 1024,
            30,
        )
        .await
        .unwrap();
        let vault = db.create_vault(10 * 1024 * 1024).await.unwrap();
        let (_, token) = db.issue(vault, true).await.unwrap();
        let who = db.authenticate(&token).await.unwrap();
        let engine =
            Engine::new(db.clone(), store, 4, 1024 * 1024, Duration::from_secs(30)).unwrap();
        Self {
            _temp: temp,
            root,
            db,
            engine,
            vault,
            who,
        }
    }
    async fn blob(&self, key: &str) -> BlobInfo {
        let info = self
            .engine
            .reserve(
                &self.who,
                self.vault,
                4,
                Sha256::digest(b"note").into(),
                key,
            )
            .await
            .unwrap();
        self.engine
            .upload(&self.who, info, Box::pin(std::io::Cursor::new(b"note")))
            .await
            .unwrap();
        info
    }
    fn put(&self, blob: Uuid, expected: u64) -> Mutation {
        Mutation::Put {
            path: "note.md".into(),
            expected,
            blob,
        }
    }
}
#[tokio::test]
async fn upload_capacity_backpressures_bounded_callers_without_false_quota_errors() {
    use tokio::io::AsyncWriteExt;
    struct StartedReader {
        inner: tokio::io::DuplexStream,
        started: std::sync::Arc<tokio::sync::Notify>,
    }
    impl tokio::io::AsyncRead for StartedReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.started.notify_one();
            std::pin::Pin::new(&mut self.inner).poll_read(cx, buffer)
        }
    }
    let f = Fixture::new().await;
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: f.root.join("blobs"),
        },
        BlockingPool::new(2).unwrap(),
        1024 * 1024,
        30,
    )
    .await
    .unwrap();
    let engine = Engine::new(f.db.clone(), store, 1, 1024 * 1024, Duration::from_secs(5)).unwrap();
    let a = engine
        .reserve(&f.who, f.vault, 4, Sha256::digest(b"note").into(), "wait-a")
        .await
        .unwrap();
    let b = engine
        .reserve(&f.who, f.vault, 4, Sha256::digest(b"note").into(), "wait-b")
        .await
        .unwrap();
    let (mut writer, reader) = tokio::io::duplex(8);
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let signal = started.clone();
    let first = engine.clone();
    let who = f.who.clone();
    let first = tokio::spawn(async move {
        first
            .upload(
                &who,
                a,
                Box::pin(StartedReader {
                    inner: reader,
                    started: signal,
                }),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    let second = engine.clone();
    let who = f.who.clone();
    let second = tokio::spawn(async move {
        second
            .upload(&who, b, Box::pin(std::io::Cursor::new(b"note")))
            .await
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!second.is_finished());
    writer.write_all(b"note").await.unwrap();
    writer.shutdown().await.unwrap();
    first.await.unwrap().unwrap();
    second.await.unwrap().unwrap();
}

#[tokio::test]
async fn concurrent_cas_and_scoped_idempotency() {
    let f = Fixture::new().await;
    let info = f.blob("upload").await;
    let (a, b) = tokio::join!(
        f.engine
            .mutate(&f.who, f.vault, "a", f.put(info.key.object, 0)),
        f.engine
            .mutate(&f.who, f.vault, "b", f.put(info.key.object, 0))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let key = if a.is_ok() { "a" } else { "b" };
    assert_eq!(
        f.engine
            .mutate(&f.who, f.vault, key, f.put(info.key.object, 0))
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        f.engine
            .mutate(&f.who, f.vault, key, f.put(info.key.object, 1))
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(
        f.engine
            .changes(&f.who, f.vault, 0, 1)
            .await
            .unwrap()
            .changes
            .len(),
        1
    );
}
#[tokio::test]
async fn update_delete_and_rename_races() {
    let f = Fixture::new().await;
    let blob = f.blob("upload").await.key.object;
    f.engine
        .mutate(&f.who, f.vault, "create", f.put(blob, 0))
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        f.engine.mutate(&f.who, f.vault, "update", f.put(blob, 1)),
        f.engine.mutate(
            &f.who,
            f.vault,
            "delete",
            Mutation::Delete {
                path: "note.md".into(),
                expected: 1
            }
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    // Restore with the actual head revision, including when the head is a tombstone.
    f.engine
        .mutate(&f.who, f.vault, "restore", f.put(blob, 2))
        .await
        .unwrap();
    let rename = Mutation::Rename {
        from: "note.md".into(),
        expected: 3,
        to: "renamed.md".into(),
        target_expected: 0,
    };
    let (a, b) = tokio::join!(
        f.engine.mutate(&f.who, f.vault, "rename", rename),
        f.engine.mutate(&f.who, f.vault, "update2", f.put(blob, 3))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let page = f.engine.changes(&f.who, f.vault, 3, 10).await.unwrap();
    assert_eq!(page.changes.len(), if a.is_ok() { 2 } else { 1 });
    if a.is_ok() {
        assert!(page.changes[0].blob.is_none());
        assert_eq!(page.changes[1].path, "renamed.md");
    }
}
#[tokio::test]
async fn cross_vault_and_revocation_on_every_surface() {
    let f = Fixture::new().await;
    let info = f.blob("upload").await;
    let other = f.db.create_vault(1024).await.unwrap();
    let (_, token) = f.db.issue(other, true).await.unwrap();
    let outsider = f.db.authenticate(&token).await.unwrap();
    let q = Queue::new(f.db.clone(), 10, 3).unwrap();
    let job = q.enqueue(&f.who, f.vault, "job").await.unwrap();
    assert!(matches!(
        f.engine.changes(&outsider, f.vault, 0, 1).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.engine.read_blob(&outsider, info.key).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.engine
            .mutate(&outsider, f.vault, "x", f.put(info.key.object, 0))
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.engine.reserve(&outsider, f.vault, 1, [0; 32], "x").await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.engine
            .upload(&outsider, info, Box::pin(std::io::Cursor::new(b"note")))
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        q.status(&outsider, job).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        q.enqueue(&outsider, f.vault, "job").await,
        Err(Error::Unauthorized)
    ));
    let (id, token) = f.db.issue(f.vault, false).await.unwrap();
    let reader = f.db.authenticate(&token).await.unwrap();
    f.engine.changes(&reader, f.vault, 0, 1).await.unwrap();
    assert!(matches!(
        f.engine
            .mutate(&reader, f.vault, "x", f.put(info.key.object, 0))
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        q.enqueue(&reader, f.vault, "x").await,
        Err(Error::Unauthorized)
    ));
    f.db.revoke(id).await.unwrap();
    assert!(matches!(
        f.engine.changes(&reader, f.vault, 0, 1).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.db.authenticate(&token).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.db.authenticate("malformed").await,
        Err(Error::Unauthorized)
    ));
}
#[tokio::test]
async fn quota_malformed_and_unready_publication() {
    let f = Fixture::new().await;
    let info = f
        .engine
        .reserve(&f.who, f.vault, 4, [0; 32], "r")
        .await
        .unwrap();
    assert_eq!(
        f.engine
            .reserve(&f.who, f.vault, 4, [0; 32], "r")
            .await
            .unwrap(),
        info
    );
    assert!(matches!(
        f.engine.reserve(&f.who, f.vault, 5, [0; 32], "r").await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        f.engine
            .upload(&f.who, info, Box::pin(std::io::Cursor::new(b"note")))
            .await,
        Err(Error::Integrity)
    ));
    assert!(matches!(
        f.engine
            .mutate(&f.who, f.vault, "write", f.put(info.key.object, 0))
            .await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        f.engine
            .reserve(&f.who, f.vault, 1024 * 1024 + 1, [0; 32], "oversize")
            .await,
        Err(Error::Limit)
    ));
    let tiny = f.db.create_vault(4096).await.unwrap();
    let (_, token) = f.db.issue(tiny, true).await.unwrap();
    let who = f.db.authenticate(&token).await.unwrap();
    f.engine
        .reserve(&who, tiny, 4, [0; 32], "first")
        .await
        .unwrap();
    assert!(matches!(
        f.engine.reserve(&who, tiny, 1, [0; 32], "second").await,
        Err(Error::Limit)
    ));
    assert!(matches!(
        f.engine.changes(&f.who, f.vault, 0, 1001).await,
        Err(Error::Invalid)
    ));
    assert!(matches!(
        f.engine.changes(&f.who, f.vault, 1, 1).await,
        Err(Error::Conflict)
    ));
    for path in ["../x", "/x", "a//b", "a/../b", "C:x", "a\\b", "a\0b", ""] {
        assert!(validate_path(path).is_err());
    }
    assert!(
        serde_json::from_str::<Mutation>(
            r#"{"kind":"Delete","path":"x","expected":0,"extra":true}"#
        )
        .is_err()
    );
}
#[tokio::test]
async fn jobs_claim_race_fairness_retry_and_quota() {
    let f = Fixture::new().await;
    let q = Queue::new(f.db.clone(), 2, 2).unwrap();
    let id = q.enqueue(&f.who, f.vault, "one").await.unwrap();
    assert_eq!(q.enqueue(&f.who, f.vault, "one").await.unwrap(), id);
    let (a, b) = tokio::join!(q.claim(), q.claim());
    let claims = [a.unwrap(), b.unwrap()];
    assert_eq!(claims.iter().filter(|c| c.is_some()).count(), 1);
    let claim = claims.into_iter().flatten().next().unwrap();
    q.complete(claim, false).await.unwrap();
    assert_eq!(q.status(&f.who, id).await.unwrap().state, "queued");
    assert!(q.claim().await.unwrap().is_none());
    f.db.run(|c| {
        c.execute("UPDATE jobs SET available=0", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let claim = q.claim().await.unwrap().unwrap();
    q.complete(claim, false).await.unwrap();
    assert_eq!(q.status(&f.who, id).await.unwrap().state, "failed");
    q.enqueue(&f.who, f.vault, "two").await.unwrap();
    assert!(matches!(
        q.enqueue(&f.who, f.vault, "three").await,
        Err(Error::Limit)
    ));
    let other = f.db.create_vault(1024).await.unwrap();
    let (_, token) = f.db.issue(other, true).await.unwrap();
    let who = f.db.authenticate(&token).await.unwrap();
    q.enqueue(&who, other, "one").await.unwrap();
    assert_eq!(q.claim().await.unwrap().unwrap().vault, other);
    for n in 1..10 {
        let delay = obsidian_sync_server::jobs::backoff(n, 29);
        assert!((2..=285).contains(&delay));
    }
}
#[tokio::test]
async fn durable_restart_recovers_upload_replay_and_running_job() {
    let f = Fixture::new().await;
    let blob = f.blob("upload").await;
    f.engine
        .mutate(&f.who, f.vault, "write", f.put(blob.key.object, 0))
        .await
        .unwrap();
    let q = Queue::new(f.db.clone(), 10, 3).unwrap();
    let id = q.enqueue(&f.who, f.vault, "one").await.unwrap();
    let old = q.claim().await.unwrap().unwrap();
    let root = f.root.clone();
    let vault = f.vault;
    let who = f.who.clone();
    drop(q);
    drop(f.engine);
    drop(f.db);
    let db = Database::open(&root.join("metadata"), BlockingPool::new(4).unwrap())
        .await
        .unwrap();
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: root.join("blobs"),
        },
        BlockingPool::new(4).unwrap(),
        1024 * 1024,
        30,
    )
    .await
    .unwrap();
    let engine = Engine::new(db.clone(), store, 4, 1024 * 1024, Duration::from_secs(30)).unwrap();
    assert_eq!(
        engine
            .mutate(
                &who,
                vault,
                "write",
                Mutation::Put {
                    path: "note.md".into(),
                    expected: 0,
                    blob: blob.key.object
                }
            )
            .await
            .unwrap(),
        1
    );
    engine
        .upload(&who, blob, Box::pin(std::io::Cursor::new(b"note")))
        .await
        .unwrap();
    let q = Queue::new(db, 10, 3).unwrap();
    assert_eq!(q.status(&who, id).await.unwrap().state, "queued");
    let new = q.claim().await.unwrap().unwrap();
    assert!(matches!(q.complete(old, true).await, Err(Error::Conflict)));
    q.complete(new, true).await.unwrap();
}
#[tokio::test]
async fn runtime_writer_lock_and_canceled_blocking_task_are_fenced() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("metadata");
    let pool = BlockingPool::new(4).unwrap();
    let db = Database::open(&root, pool.clone()).await.unwrap();
    assert!(matches!(
        Database::open(&root, pool.clone()).await,
        Err(Error::WriterActive)
    ));
    let (entered, rx) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        db.run(move |_| {
            let _ = entered.send(());
            wait.recv().unwrap();
            Ok(())
        })
        .await
    });
    rx.await.unwrap();
    task.abort();
    let _ = task.await;
    assert!(matches!(
        Database::open(&root, pool.clone()).await,
        Err(Error::WriterActive)
    ));
    release.send(()).unwrap();
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if Database::open(&root, pool.clone()).await.is_ok() {
            return;
        }
    }
    panic!("writer lock was not released");
}
#[tokio::test]
async fn sqlite_backup_restore() {
    let f = Fixture::new().await;
    let blob = f.blob("upload").await;
    f.engine
        .mutate(&f.who, f.vault, "create", f.put(blob.key.object, 0))
        .await
        .unwrap();
    let restore = f.root.join("restored");
    tokio::fs::create_dir(&restore).await.unwrap();
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&restore, std::fs::Permissions::from_mode(0o700))
        .await
        .unwrap();
    f.db.backup(restore.join("state.sqlite3")).await.unwrap();
    let db = Database::open(&restore, BlockingPool::new(2).unwrap())
        .await
        .unwrap();
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: f.root.join("blobs"),
        },
        BlockingPool::new(2).unwrap(),
        1024 * 1024,
        30,
    )
    .await
    .unwrap();
    let engine = Engine::new(db, store, 2, 1024 * 1024, Duration::from_secs(30)).unwrap();
    assert_eq!(
        engine
            .changes(&f.who, f.vault, 0, 100)
            .await
            .unwrap()
            .changes
            .len(),
        1
    );
    let (info, mut reader) = engine.read_blob(&f.who, blob.key).await.unwrap();
    obsidian_sync_server::storage::copy_verified(&mut reader, &mut tokio::io::sink(), info)
        .await
        .unwrap();
}
proptest! {
    #[test]
    fn accepted_paths_are_relative_normal_components(path in ".{0,1500}"){
        if validate_path(&path).is_ok(){prop_assert!(!std::path::Path::new(&path).is_absolute());prop_assert!(path.split('/').all(|c|!c.is_empty()&&c!="."&&c!=".."));prop_assert!(!path.contains('\\'));}
    }
    #[test]
    fn traversal_never_passes(parts in prop::collection::vec("[a-z]{1,12}",0..10)){
        let path=format!("{}/../escape",parts.join("/"));prop_assert!(validate_path(&path).is_err());
    }
}
