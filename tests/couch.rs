use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use obsidian_sync_server::{
    config::{Config, StorageConfig},
    couch::{Couch, http},
    db::Database,
    storage::{BlockingPool, Store},
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;
fn counter(value: &Value) -> i64 {
    value
        .as_str()
        .unwrap()
        .split_once('-')
        .unwrap()
        .0
        .parse()
        .unwrap()
}
struct Fixture {
    _temp: TempDir,
    app: Router,
    db: Database,
    vault: Uuid,
    auth: String,
    _stop: tokio::sync::watch::Sender<bool>,
}
impl Fixture {
    async fn new() -> Self {
        Self::custom(|_| {}).await
    }
    async fn custom(configure: impl FnOnce(&mut Config)) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let mut config: Config = toml::from_str(include_str!("../config/filesystem.toml")).unwrap();
        config.metadata_dir = root.join("metadata");
        config.storage = StorageConfig::Filesystem {
            root: root.join("blobs"),
        };
        config.http.allowed_origins = vec!["app://obsidian.md".into()];
        configure(&mut config);
        let pool = BlockingPool::new(4).unwrap();
        let db = Database::open(&config.metadata_dir, pool.clone())
            .await
            .unwrap();
        let vault = db
            .create_database("vault", 100 * 1024 * 1024)
            .await
            .unwrap();
        let (id, token) = db.issue(vault, true).await.unwrap();
        let auth = format!("Basic {}", STANDARD.encode(format!("{id}:{token}")));
        let store = Store::open(&config.storage, pool, config.max_blob_bytes, 30)
            .await
            .unwrap();
        let (tx, rx) = tokio::sync::watch::channel(false);
        let couch = Couch::new(db.clone(), store, &config, rx).unwrap();
        let app = http::router(couch).unwrap();
        Self {
            _temp: temp,
            app,
            db,
            vault,
            auth,
            _stop: tx,
        }
    }
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
        request(&self.app, &self.auth, method, path, body).await
    }
    async fn import(&self, doc: Value) {
        let (status, value) = self
            .call(
                "POST",
                "/vault/_bulk_docs",
                Some(json!({"new_edits":false,"docs":[doc]})),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{value}");
        assert_eq!(value, json!([]));
    }
}
async fn request(
    app: &Router,
    auth: &str,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.map_or_else(Body::empty, |v| Body::from(serde_json::to_vec(&v).unwrap())))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}
#[tokio::test]
async fn failed_authentication_cannot_spend_authenticated_rate_budgets() {
    let f = Fixture::custom(|config| {
        config.http.burst = 4;
        config.http.requests_per_minute = 1;
    })
    .await;
    assert_eq!(f.call("GET", "/vault", None).await.0, 200);
    let wrong_username = {
        let encoded = f.auth.strip_prefix("Basic ").unwrap();
        let pair = String::from_utf8(STANDARD.decode(encoded).unwrap()).unwrap();
        let (_, token) = pair.split_once(':').unwrap();
        format!(
            "Basic {}",
            STANDARD.encode(format!("{}:{token}", Uuid::new_v4()))
        )
    };
    for _ in 0..8 {
        for auth in ["", "Bearer invalid", wrong_username.as_str()] {
            assert_eq!(request(&f.app, auth, "GET", "/vault", None).await.0, 401);
        }
    }
    // Exactly the remaining authenticated burst is available, not an unbounded bypass.
    for _ in 0..3 {
        assert_eq!(f.call("GET", "/vault", None).await.0, 200);
    }
    assert_eq!(f.call("GET", "/vault", None).await.0, 429);
    assert_eq!(
        request(&f.app, "", "GET", "/health/ready", None).await.0,
        204
    );
}

#[tokio::test]
async fn actual_couch_revisions_conflicts_deletion_and_resurrection() {
    let f = Fixture::new().await;
    f.import(json!({"_id":"note.md","_rev":"1-root","type":"plain","value":"base"}))
        .await;
    for (rev, text) in [("2-left", "left"), ("2-right", "right")] {
        f.import(json!({"_id":"note.md","_rev":rev,"_revisions":{"start":2,"ids":[rev.split_once('-').unwrap().1,"root"]},"type":"plain","value":text})).await;
    }
    let (status, doc) = f
        .call("GET", "/vault/note.md?conflicts=true&revs=true", None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(doc["_rev"], "2-right");
    assert_eq!(doc["_conflicts"], json!(["2-left"]));
    assert_eq!(doc["_revisions"]["ids"], json!(["right", "root"]));
    let (_, page) = f
        .call(
            "GET",
            "/vault/_changes?style=all_docs&include_docs=true",
            None,
        )
        .await;
    assert_eq!(page["results"].as_array().unwrap().len(), 1);
    assert_eq!(page["results"][0]["changes"].as_array().unwrap().len(), 2);
    let (status, deleted) = f.call("DELETE", "/vault/note.md?rev=2-right", None).await;
    assert_eq!(status, 201);
    let (_, live) = f.call("GET", "/vault/note.md", None).await;
    assert_eq!(live["_rev"], "2-left");
    let tombstone = deleted["rev"].as_str().unwrap();
    let (status, dead) = f
        .call(
            "GET",
            &format!("/vault/note.md?rev={tombstone}&revs=true"),
            None,
        )
        .await;
    assert_eq!(status, 200);
    assert_eq!(dead["_deleted"], true);
    assert_eq!(dead["_revisions"]["start"], 3);
    assert_eq!(
        f.call("DELETE", "/vault/note.md?rev=2-left", None).await.0,
        201
    );
    assert_eq!(f.call("GET", "/vault/note.md", None).await.0, 404);
    assert_eq!(
        f.call("PUT", "/vault/note.md", Some(json!({"value":"restored"})))
            .await
            .0,
        201
    );
    let (_, history) = f.call("GET", "/vault/note.md?rev=1-root", None).await;
    assert_eq!(history["value"], "base");
}
#[tokio::test]
async fn token_dense_json_and_aggregate_read_trees_have_independent_memory_budgets() {
    let f = Fixture::new().await;
    assert_eq!(
        f.call("PUT", "/vault/dense", Some(json!({"data":vec![0;70000]})))
            .await
            .0,
        413
    );
    for i in 0..64 {
        f.import(json!({"_id":format!("tree-{i}"),"_rev":"1-a","value":vec![0;8192]}))
            .await;
    }
    let docs = (0..64)
        .map(|i| json!({"id":format!("tree-{i}")}))
        .collect::<Vec<_>>();
    // Wire output would be only ~1 MiB, but constructing all trees exceeds the
    // separate conservative working-set budget. Never omit requested bulk rows.
    assert_eq!(
        f.call("POST", "/vault/_bulk_get", Some(json!({"docs":docs})))
            .await
            .0,
        413
    );
    let mut cursor = "0".to_owned();
    let mut total = 0;
    loop {
        let (status, page) = f
            .call(
                "GET",
                &format!("/vault/_changes?include_docs=true&limit=64&since={cursor}"),
                None,
            )
            .await;
        assert_eq!(status, 200);
        let count = page["results"].as_array().unwrap().len();
        assert!(count > 0);
        total += count;
        cursor = page["last_seq"].as_str().unwrap().to_owned();
        if page["pending"] == 0 {
            break;
        }
        assert!(count < 64);
    }
    assert_eq!(total, 64);
}

#[tokio::test]
async fn bounded_bursts_queue_without_false_upload_quota_or_admission_errors() {
    let f = Fixture::new().await;
    futures_util::future::join_all((0..16).map(|i| {
        let fixture = &f;
        async move {
            fixture
                .import(json!({"_id":format!("burst-{i}"),"_rev":"1-a","value":"x".repeat(1024)}))
                .await
        }
    }))
    .await;
    assert_eq!(f.call("GET", "/vault", None).await.1["doc_count"], 16);
}

#[tokio::test]
async fn imported_replay_body_and_ancestry_are_not_overwritten() {
    let f = Fixture::new().await;
    let doc = json!({"_id":"a","_rev":"2-b","_revisions":{"start":2,"ids":["b","a"]},"value":1});
    f.import(doc.clone()).await;
    let (_, before) = f.call("GET", "/vault", None).await;
    f.import(doc).await;
    let (_, after) = f.call("GET", "/vault", None).await;
    assert_eq!(before["update_seq"], after["update_seq"]);
    f.import(json!({"_id":"a","_rev":"2-b","value":2})).await;
    assert_eq!(f.call("GET", "/vault/a", None).await.1["value"], 1);
    {
        let doc = json!({"_id":"a","_rev":"2-b","_revisions":{"start":2,"ids":["b","different"]},"value":1});
        let (_, result) = f
            .call(
                "POST",
                "/vault/_bulk_docs",
                Some(json!({"new_edits":false,"docs":[doc]})),
            )
            .await;
        assert_eq!(result[0]["status"], 409);
    }
    let (_, diff) = f
        .call(
            "POST",
            "/vault/_revs_diff",
            Some(json!({"a":["1-a","2-b","2-c"]})),
        )
        .await;
    assert_eq!(diff["a"]["missing"], json!(["1-a", "2-c"]));
    let (_, rows) = f
        .call(
            "POST",
            "/vault/_bulk_get?revs=true",
            Some(json!({"docs":[{"id":"a","rev":"2-b"},{"id":"a","rev":"2-c"}]})),
        )
        .await;
    assert_eq!(rows["results"][0]["docs"][0]["ok"]["value"], 1);
    assert_eq!(rows["results"][1]["docs"][0]["error"]["error"], "not_found");
    // A damaged half-reference must not be mistaken for an unavailable ancestry stub.
    f.db.run(|c| {
        c.execute(
            "UPDATE couch_revisions SET digest=NULL WHERE id='a' AND rev='2-b'",
            [],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    let (_, replay) = f
        .call(
            "POST",
            "/vault/_bulk_docs",
            Some(json!({"new_edits":false,"docs":[{"_id":"a","_rev":"2-b","value":3}]})),
        )
        .await;
    assert_eq!(replay[0]["status"], 500);
}
#[tokio::test]
async fn normal_update_races_and_local_checkpoints_are_atomic() {
    let f = Fixture::new().await;
    let (status, created) = f.call("PUT", "/vault/race", Some(json!({"v":1}))).await;
    assert_eq!(status, 201);
    let body = json!({"_rev":created["rev"],"v":2});
    let (a, b) = tokio::join!(
        f.call("PUT", "/vault/race", Some(body.clone())),
        f.call("PUT", "/vault/race", Some(body))
    );
    assert_eq!([a.0, b.0].iter().filter(|s| **s == 201).count(), 1);
    assert!([a.0, b.0].contains(&StatusCode::CONFLICT));
    let (status, local) = f
        .call(
            "PUT",
            "/vault/_local/checkpoint",
            Some(json!({"last_seq":2})),
        )
        .await;
    assert_eq!(status, 201);
    assert_eq!(local["rev"], "0-1");
    let body = json!({"_rev":"0-1","last_seq":3});
    let (a, b) = tokio::join!(
        f.call("PUT", "/vault/_local/checkpoint", Some(body.clone())),
        f.call("PUT", "/vault/_local/checkpoint", Some(body))
    );
    assert_eq!([a.0, b.0].iter().filter(|s| **s == 201).count(), 1);
    let (_, feed) = f.call("GET", "/vault/_changes", None).await;
    assert_eq!(feed["results"].as_array().unwrap().len(), 1);
    let (_, doc) = f.call("GET", "/vault/_local/checkpoint", None).await;
    assert_eq!(doc["_rev"], "0-2");
    assert_eq!(
        f.call("DELETE", "/vault/_local/checkpoint?rev=0-2", None)
            .await
            .0,
        201
    );
    assert_eq!(f.call("GET", "/vault/_local/checkpoint", None).await.0, 404);
}
#[tokio::test]
async fn cross_vault_readonly_revoked_and_wrong_basic_username_fail() {
    let f = Fixture::new().await;
    f.import(json!({"_id":"secret","_rev":"1-a","value":"private"}))
        .await;
    let other = f.db.create_database("other", 100000).await.unwrap();
    let (id, token) = f.db.issue(other, true).await.unwrap();
    let auth = format!("Basic {}", STANDARD.encode(format!("{id}:{token}")));
    for (method, path, body) in [
        ("GET", "/vault", None),
        ("GET", "/vault/secret?rev=1-a", None),
        ("GET", "/vault/_changes", None),
        ("GET", "/vault/_all_docs?include_docs=true", None),
        ("GET", "/vault/_local/checkpoint", None),
        (
            "POST",
            "/vault/_bulk_get",
            Some(json!({"docs":[{"id":"secret"}]})),
        ),
        ("POST", "/vault/_revs_diff", Some(json!({"secret":["1-a"]}))),
        ("PUT", "/vault/new", Some(json!({"value":1}))),
    ] {
        assert_eq!(request(&f.app, &auth, method, path, body).await.0, 403);
    }
    let (id, token) = f.db.issue(f.vault, false).await.unwrap();
    let auth = format!("Basic {}", STANDARD.encode(format!("{id}:{token}")));
    assert_eq!(
        request(&f.app, &auth, "GET", "/vault/secret", None).await.0,
        200
    );
    assert_eq!(
        request(
            &f.app,
            &auth,
            "PUT",
            "/vault/secret",
            Some(json!({"_rev":"1-a"}))
        )
        .await
        .0,
        403
    );
    f.db.revoke(id).await.unwrap();
    assert_eq!(
        request(&f.app, &auth, "GET", "/vault/secret", None).await.0,
        401
    );
    let wrong = format!(
        "Basic {}",
        STANDARD.encode(format!("{}:{token}", Uuid::new_v4()))
    );
    assert_eq!(request(&f.app, &wrong, "GET", "/", None).await.0, 401);
}
#[tokio::test]
async fn pagination_current_changes_selector_and_explicit_limits() {
    let f = Fixture::new().await;
    for i in 0..5 {
        f.import(
            json!({"_id":format!("doc-{i}"),"_rev":"1-a","type":if i%2==0{"leaf"}else{"plain"}}),
        )
        .await;
    }
    let (_, page) = f.call("GET", "/vault/_changes?limit=2", None).await;
    assert_eq!(counter(&page["last_seq"]), 2);
    assert_eq!(page["pending"], 3);
    let cursor = page["last_seq"].as_str().unwrap();
    let (_, page) = f
        .call(
            "GET",
            &format!("/vault/_changes?since={cursor}&limit=2"),
            None,
        )
        .await;
    assert_eq!(counter(&page["last_seq"]), 4);
    assert_eq!(page["pending"], 1);
    let (_, page) = f
        .call(
            "POST",
            "/vault/_changes?filter=_selector&include_docs=true",
            Some(json!({"selector":{"type":{"$ne":"leaf"}}})),
        )
        .await;
    assert_eq!(page["results"].as_array().unwrap().len(), 2);
    assert_eq!(counter(&page["last_seq"]), 5);
    assert_eq!(
        f.call(
            "GET",
            &format!("/vault/_changes?since=99999-{}", f.vault),
            None
        )
        .await
        .0,
        400
    );
    let (_, keys) = f
        .call(
            "POST",
            "/vault/_all_docs?include_docs=true",
            Some(json!({"keys":["absent","doc-1"]})),
        )
        .await;
    assert_eq!(keys["rows"][0]["error"], "not_found");
    assert_eq!(keys["rows"][1]["doc"]["type"], "plain");
    let docs = (0..129)
        .map(|i| json!({"_id":format!("too-many-{i}")}))
        .collect::<Vec<_>>();
    assert_eq!(
        f.call("POST", "/vault/_bulk_docs", Some(json!({"docs":docs})))
            .await
            .0,
        413
    );
    assert_eq!(
        f.call(
            "PUT",
            "/vault/oversize",
            Some(json!({"content":"x".repeat(1024*1024)}))
        )
        .await
        .0,
        413
    );
    assert_eq!(
        f.call("PUT", "/vault/bad", Some(json!({"_id":"different"})))
            .await
            .0,
        400
    );
    assert_eq!(
        f.call(
            "POST",
            "/vault/_changes?filter=_selector",
            Some(json!({"selector":{"data":{"$regex":".*"}}}))
        )
        .await
        .0,
        501
    );
}
#[tokio::test]
async fn bootstrap_reset_archives_history_fences_old_keys_and_epochs_and_preserves_quota() {
    let f = Fixture::new().await;
    let credential = String::from_utf8(
        STANDARD
            .decode(f.auth.strip_prefix("Basic ").unwrap())
            .unwrap(),
    )
    .unwrap();
    let principal: Uuid = credential.split_once(':').unwrap().0.parse().unwrap();
    f.import(json!({"_id":"old","_rev":"1-a","value":"archived"}))
        .await;
    f.call(
        "PUT",
        "/vault/_local/checkpoint",
        Some(json!({"last_seq":"old"})),
    )
    .await;
    let old_cursor = f.call("GET", "/vault", None).await.1["update_seq"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(f.call("DELETE", "/vault", None).await.0, 403);
    f.db.allow_database_reset(principal, f.vault).await.unwrap();
    assert_eq!(f.call("DELETE", "/vault", None).await.0, 200);
    assert_eq!(f.call("GET", "/vault", None).await.0, 404);
    assert_eq!(f.call("PUT", "/vault", None).await.0, 201);
    assert_eq!(f.call("GET", "/vault/old", None).await.0, 404);
    assert_eq!(f.call("GET", "/vault/_local/checkpoint", None).await.0, 404);
    assert_eq!(
        f.call("GET", &format!("/vault/_changes?since={old_cursor}"), None)
            .await
            .0,
        400
    );
    assert!(f.db.issue(f.vault, true).await.is_err());
    let current = f.db.databases().await.unwrap()[0].1;
    assert_ne!(current, f.vault);
    let old = f.vault;
    f.db.run(move |c| {
        let count: i64 = c.query_row(
            "SELECT count(*) FROM couch_revisions WHERE vault=?1",
            [old.to_string()],
            |r| r.get(0),
        )?;
        assert_eq!(count, 1);
        let count: i64 = c.query_row(
            "SELECT count(*) FROM couch_local WHERE vault=?1",
            [old.to_string()],
            |r| r.get(0),
        )?;
        assert_eq!(count, 1);
        let count: i64 = c.query_row(
            "SELECT count(*) FROM grants WHERE vault=?1",
            [old.to_string()],
            |r| r.get(0),
        )?;
        assert_eq!(count, 0);
        let used: i64 = c.query_row(
            "SELECT allocated FROM vaults WHERE id=?1",
            [current.to_string()],
            |r| r.get(0),
        )?;
        let previous: i64 = c.query_row(
            "SELECT allocated FROM vaults WHERE id=?1",
            [old.to_string()],
            |r| r.get(0),
        )?;
        assert!(used >= previous + 4096);
        Ok(())
    })
    .await
    .unwrap();
    f.db.create_database("other", 100000).await.unwrap();
    assert_eq!(f.call("DELETE", "/other", None).await.0, 403);
    for _ in 1..16 {
        assert_eq!(f.call("DELETE", "/vault", None).await.0, 200);
        assert_eq!(f.call("PUT", "/vault", None).await.0, 201);
    }
    assert_eq!(f.call("DELETE", "/vault", None).await.0, 507);
    f.db.revoke(principal).await.unwrap();
    assert_eq!(f.call("GET", "/vault", None).await.0, 401);
}

#[tokio::test]
async fn failed_publication_rolls_back_dag_sequence_and_recovers_same_upload() {
    let f = Fixture::new().await;
    f.db.run(|c|{c.execute_batch("CREATE TRIGGER interrupted BEFORE INSERT ON couch_heads BEGIN SELECT RAISE(ABORT,'injected failure'); END;")?;Ok(())}).await.unwrap();
    let doc = json!({"_id":"interrupted","_rev":"2-new","_revisions":{"start":2,"ids":["new","old"]},"value":"retained"});
    let (_, failed) = f
        .call(
            "POST",
            "/vault/_bulk_docs",
            Some(json!({"new_edits":false,"docs":[doc.clone()]})),
        )
        .await;
    assert_eq!(failed[0]["status"], 500);
    assert_eq!(f.call("GET", "/vault/interrupted", None).await.0, 404);
    assert_eq!(
        counter(&f.call("GET", "/vault", None).await.1["update_seq"]),
        0
    );
    f.db.run(|c| {
        let count: i64 = c.query_row("SELECT count(*) FROM couch_revisions", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        c.execute_batch("DROP TRIGGER interrupted;")?;
        Ok(())
    })
    .await
    .unwrap();
    f.import(doc).await;
    assert_eq!(
        counter(&f.call("GET", "/vault", None).await.1["update_seq"]),
        1
    );
    f.db.run(|c| {
        let count: i64 = c.query_row("SELECT count(*) FROM blobs", [], |r| r.get(0))?;
        assert_eq!(count, 1);
        Ok(())
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn couch_backup_restore_preserves_active_epoch_archives_auth_and_content() {
    let f = Fixture::new().await;
    let credential = String::from_utf8(
        STANDARD
            .decode(f.auth.strip_prefix("Basic ").unwrap())
            .unwrap(),
    )
    .unwrap();
    let (principal, token) = credential.split_once(':').unwrap();
    let principal: Uuid = principal.parse().unwrap();
    let token = token.to_owned();
    f.import(json!({"_id":"before","_rev":"1-a","value":"archive"}))
        .await;
    f.db.allow_database_reset(principal, f.vault).await.unwrap();
    assert_eq!(f.call("DELETE", "/vault", None).await.0, 200);
    assert_eq!(f.call("PUT", "/vault", None).await.0, 201);
    f.import(json!({"_id":"current","_rev":"1-b","value":"durable"}))
        .await;
    let sequence = f.call("GET", "/vault", None).await.1["update_seq"].clone();
    f.call(
        "PUT",
        "/vault/_local/current",
        Some(json!({"last_seq":sequence})),
    )
    .await;
    let root = f._temp.path().canonicalize().unwrap();
    let restored = root.join("restored");
    let source = root.join("blobs");
    let target = restored.join("blobs");
    let metadata = restored.join("metadata");
    let pool = BlockingPool::new(2).unwrap();
    let dir = metadata.clone();
    pool.run(move || {
        obsidian_sync_server::storage::private_root(&dir)?;
        Ok(())
    })
    .await
    .unwrap();
    f.db.backup(metadata.join("state.sqlite3")).await.unwrap();
    pool.run(move || {
        let result = std::process::Command::new("cp")
            .arg("-R")
            .arg(source)
            .arg(target)
            .status()?;
        if !result.success() {
            return Err(obsidian_sync_server::Error::Backend);
        }
        Ok(())
    })
    .await
    .unwrap();
    let db = Database::open(&metadata, pool.clone()).await.unwrap();
    let who = db.authenticate(&token).await.unwrap();
    let mut config: Config = toml::from_str(include_str!("../config/filesystem.toml")).unwrap();
    config.metadata_dir = metadata;
    config.storage = StorageConfig::Filesystem {
        root: restored.join("blobs"),
    };
    let store = Store::open(&config.storage, pool, config.max_blob_bytes, 30)
        .await
        .unwrap();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let couch = Couch::new(db.clone(), store, &config, rx).unwrap();
    let current = couch.resolve(&who, "vault", false).await.unwrap();
    assert_eq!(
        couch
            .get(&who, current, "current", Default::default())
            .await
            .unwrap()["value"],
        "durable"
    );
    let app = http::router(couch).unwrap();
    assert_eq!(
        request(&app, &f.auth, "GET", "/vault", None).await.1["update_seq"],
        sequence
    );
    assert_eq!(
        request(&app, &f.auth, "GET", "/vault/_local/current", None)
            .await
            .1["last_seq"],
        sequence
    );
    assert_eq!(
        request(&app, &f.auth, "GET", "/vault/before", None).await.0,
        404
    );
    db.run(|c| {
        let count: i64 = c.query_row("SELECT count(*) FROM couch_archives", [], |r| r.get(0))?;
        assert_eq!(count, 1);
        Ok(())
    })
    .await
    .unwrap();
    f.import(json!({"_id":"after-snapshot","_rev":"1-c"})).await;
    let future = f.call("GET", "/vault", None).await.1["update_seq"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        request(
            &app,
            &f.auth,
            "GET",
            &format!("/vault/_changes?since={future}"),
            None
        )
        .await
        .0,
        400
    );
}

#[tokio::test]
async fn health_is_ready_but_all_data_requires_authentication() {
    let f = Fixture::new().await;
    for path in ["/health/live", "/health/ready"] {
        let r = f
            .app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
    }
    assert_eq!(request(&f.app, "", "GET", "/", None).await.0, 401);
    assert_eq!(
        request(&f.app, "", "GET", "/vault/_changes", None).await.0,
        401
    );
    assert_eq!(
        f.call("GET", "/_node/nonode@nohost/_config", None).await.0,
        501
    );
    assert_eq!(f.call("DELETE", "/vault", None).await.0, 403);
}

#[tokio::test]
async fn waiting_feeds_cannot_starve_writes() {
    let f = Fixture::custom(|c| c.http.max_requests = 2).await;
    let mut polls = Vec::new();
    for _ in 0..12 {
        let app = f.app.clone();
        let auth = f.auth.clone();
        polls.push(tokio::spawn(async move {
            request(
                &app,
                &auth,
                "GET",
                "/vault/_changes?feed=longpoll&timeout=2000",
                None,
            )
            .await
        }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        f.import(json!({"_id":"wakeup","_rev":"1-a"})),
    )
    .await
    .unwrap();
    for poll in polls {
        let (status, body) = poll.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body["results"].as_array().unwrap().len(), 1);
    }
}
#[tokio::test]
async fn malformed_scalar_csrf_limits_and_latest_descendants() {
    let f = Fixture::new().await;
    for body in [json!(null), json!("scalar"), json!([])] {
        assert_eq!(f.call("POST", "/vault", Some(body)).await.0, 400);
    }
    let (status, result) = f
        .call(
            "POST",
            "/vault/_bulk_docs",
            Some(json!({"docs":[null,3,[]]})),
        )
        .await;
    assert_eq!(status, 201);
    assert!(
        result
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["status"] == 400)
    );
    let req = Request::builder()
        .method("PUT")
        .uri("/vault/csrf")
        .header(header::AUTHORIZATION, &f.auth)
        .header(header::ORIGIN, "https://malicious.example")
        .body(Body::from("{\"value\":1}"))
        .unwrap();
    assert_eq!(f.app.clone().oneshot(req).await.unwrap().status(), 403);
    assert_eq!(f.call("GET", "/vault/csrf", None).await.0, 404);
    f.import(json!({"_id":"latest","_rev":"1-root","value":"original"}))
        .await;
    for suffix in ["a", "b"] {
        f.import(json!({"_id":"latest","_rev":format!("2-{suffix}"),"_revisions":{"start":2,"ids":[suffix,"root"]},"value":suffix})).await;
    }
    let (_, latest) = f
        .call(
            "GET",
            "/vault/latest?rev=1-root&latest=true&revs=true",
            None,
        )
        .await;
    assert_eq!(latest["_rev"], "2-b");
    let (_, bulk) = f
        .call(
            "POST",
            "/vault/_bulk_get?latest=true&revs=true",
            Some(json!({"docs":[{"id":"latest","rev":"1-root"}]})),
        )
        .await;
    assert_eq!(bulk["results"][0]["docs"].as_array().unwrap().len(), 2);
    let limited = Fixture::custom(|c| {
        c.http.burst = 2;
        c.http.requests_per_minute = 1;
    })
    .await;
    assert_eq!(limited.call("GET", "/", None).await.0, 200);
    assert_eq!(limited.call("GET", "/", None).await.0, 200);
    assert_eq!(limited.call("GET", "/", None).await.0, 429);
}

#[tokio::test]
async fn longpoll_wakeup_shutdown_and_cors() {
    let f = Fixture::new().await;
    let vault = f.vault;
    let app = f.app.clone();
    let auth = f.auth.clone();
    let pending = tokio::spawn(async move {
        request(
            &app,
            &auth,
            "GET",
            "/vault/_changes?feed=longpoll&since=0&timeout=2000",
            None,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    f.import(json!({"_id":"wake","_rev":"1-a"})).await;
    let (status, feed) = pending.await.unwrap();
    assert_eq!(status, 200);
    assert_eq!(feed["results"].as_array().unwrap().len(), 1);
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/vault/_bulk_docs")
        .header(header::ORIGIN, "app://obsidian.md")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .header(
            header::ACCESS_CONTROL_REQUEST_HEADERS,
            "authorization,content-type",
        )
        .body(Body::empty())
        .unwrap();
    let response = f.app.clone().oneshot(preflight).await.unwrap();
    assert_eq!(
        response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
        "app://obsidian.md"
    );
    let app = f.app.clone();
    let auth = f.auth.clone();
    let pending = tokio::spawn(async move {
        request(
            &app,
            &auth,
            "GET",
            &format!("/vault/_changes?feed=longpoll&since=1-{vault}"),
            None,
        )
        .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    f._stop.send(true).unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(1), pending)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(matches!(
        status,
        StatusCode::OK | StatusCode::SERVICE_UNAVAILABLE
    ));
    assert_eq!(f.call("GET", "/health/ready", None).await.0, 503);
}
