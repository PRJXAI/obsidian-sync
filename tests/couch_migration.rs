use obsidian_sync_server::{
    Error,
    config::StorageConfig,
    db::Database,
    storage::{BlockingPool, Store},
    sync::Engine,
};
use std::time::Duration;
#[tokio::test]
async fn schema_one_upgrade_preserves_credentials_legacy_history_and_lock() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let pool = BlockingPool::new(2).unwrap();
    let db = Database::open(&root.join("metadata"), pool.clone())
        .await
        .unwrap();
    let vault = db.create_vault(100000).await.unwrap();
    let (_, token) = db.issue(vault, true).await.unwrap();
    db.run(move|c|{
        c.execute("INSERT INTO heads(vault,path,revision,blob) VALUES(?1,'legacy.md',1,NULL)",[vault.to_string()])?;
        c.execute("INSERT INTO changes(vault,revision,path,blob) VALUES(?1,1,'legacy.md',NULL)",[vault.to_string()])?;
        c.execute("UPDATE vaults SET revision=1 WHERE id=?1",[vault.to_string()])?;
        c.execute_batch("DROP TABLE couch_heads; DROP TABLE couch_revisions; DROP TABLE couch_local; DROP TABLE couch_databases; DROP TABLE server_meta; PRAGMA user_version=1;")?;Ok(())
    }).await.unwrap();
    drop(db);
    let db = Database::open(&root.join("metadata"), pool.clone())
        .await
        .unwrap();
    let who = db.authenticate(&token).await.unwrap();
    db.run(|c| {
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, 3);
        Ok(())
    })
    .await
    .unwrap();
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: root.join("blobs"),
        },
        pool.clone(),
        1024 * 1024,
        30,
    )
    .await
    .unwrap();
    let engine = Engine::new(db.clone(), store, 2, 1024 * 1024, Duration::from_secs(30)).unwrap();
    let changes = engine.changes(&who, vault, 0, 10).await.unwrap();
    assert_eq!(changes.changes[0].path, "legacy.md");
    assert!(changes.changes[0].blob.is_none());
    assert!(matches!(
        Database::open(&root.join("metadata"), pool).await,
        Err(Error::WriterActive)
    ));
    db.create_database("new-sync", 100000).await.unwrap();
}
#[tokio::test]
async fn schema_two_upgrade_keeps_alias_grants_and_instance_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("metadata");
    let pool = BlockingPool::new(2).unwrap();
    let db = Database::open(&root, pool.clone()).await.unwrap();
    let vault = db.create_database("existing", 100000).await.unwrap();
    let (_, token) = db.issue(vault, true).await.unwrap();
    let identity = db
        .run(|c| {
            Ok(c.query_row(
                "SELECT value FROM server_meta WHERE key='instance'",
                [],
                |r| r.get::<_, String>(0),
            )?)
        })
        .await
        .unwrap();
    db.run(|c| {
        c.execute_batch("ALTER TABLE couch_databases DROP COLUMN active; PRAGMA user_version=2;")?;
        Ok(())
    })
    .await
    .unwrap();
    drop(db);
    let db = Database::open(&root, pool).await.unwrap();
    db.authenticate(&token).await.unwrap();
    let databases = db.databases().await.unwrap();
    assert_eq!(databases, vec![("existing".into(), vault, true)]);
    db.run(move |c| {
        let saved: String = c.query_row(
            "SELECT value FROM server_meta WHERE key='instance'",
            [],
            |r| r.get(0),
        )?;
        assert_eq!(saved, identity);
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, 3);
        Ok(())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_schema_is_rejected_without_downgrade() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap().join("metadata");
    let pool = BlockingPool::new(2).unwrap();
    let db = Database::open(&root, pool.clone()).await.unwrap();
    db.run(|c| {
        c.execute_batch("PRAGMA user_version=4;")?;
        Ok(())
    })
    .await
    .unwrap();
    drop(db);
    assert!(matches!(
        Database::open(&root, pool.clone()).await,
        Err(Error::Invalid)
    ));
    pool.run(move || {
        let c = rusqlite::Connection::open(root.join("state.sqlite3"))?;
        let version: i64 = c.pragma_query_value(None, "user_version", |r| r.get(0))?;
        assert_eq!(version, 4);
        Ok(())
    })
    .await
    .unwrap();
}
