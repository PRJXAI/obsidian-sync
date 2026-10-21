//! Reproducible persistence-core benchmark, not a plugin/network benchmark.
use obsidian_sync_server::{
    Result,
    config::StorageConfig,
    db::Database,
    storage::{BlockingPool, Store},
    sync::{Engine, Mutation},
};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::AsyncReadExt;

fn report(name: &str, mut samples: Vec<Duration>, elapsed: Duration, bytes: u64) {
    samples.sort();
    let n = samples.len();
    let q = |p: usize| samples[(n * p / 100).min(n - 1)].as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::json!({"workload":name,"operations":n,"elapsed_seconds":elapsed.as_secs_f64(),"ops_per_second":n as f64/elapsed.as_secs_f64(),"p50_ms":q(50),"p95_ms":q(95),"p99_ms":q(99),"bytes_per_second":bytes as f64/elapsed.as_secs_f64()})
    );
}
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().canonicalize()?;
    let pool = BlockingPool::new(4)?;
    let db = Database::open(&root.join("metadata"), pool.clone()).await?;
    let vault = db.create_vault(1024 * 1024 * 1024).await?;
    let (_, token) = db.issue(vault, true).await?;
    let who = db.authenticate(&token).await?;
    let store = Store::open(
        &StorageConfig::Filesystem {
            root: root.join("blobs"),
        },
        pool.clone(),
        64 * 1024 * 1024,
        300,
    )
    .await?;
    let engine = Arc::new(Engine::new(
        db,
        store,
        4,
        64 * 1024 * 1024,
        Duration::from_secs(300),
    )?);
    let start = Instant::now();
    let mut samples = Vec::new();
    let mut shared = None;
    for i in 0..200 {
        let started = Instant::now();
        let mut bytes = vec![42_u8; 1024];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        let info = engine
            .reserve(
                &who,
                vault,
                1024,
                Sha256::digest(&bytes).into(),
                &format!("upload-{i}"),
            )
            .await?;
        engine
            .upload(&who, info, Box::pin(std::io::Cursor::new(bytes)))
            .await?;
        engine
            .mutate(
                &who,
                vault,
                &format!("write-{i}"),
                Mutation::Put {
                    path: format!("note-{i}.md"),
                    expected: 0,
                    blob: info.key.object,
                },
            )
            .await?;
        samples.push(started.elapsed());
        shared = Some(info.key.object);
    }
    report(
        "small-note-full-commit-1KiB",
        samples,
        start.elapsed(),
        200 * 1024,
    );
    let size = 64 * 1024 * 1024;
    let digest = pool
        .run(move || {
            let mut hash = Sha256::new();
            for _ in 0..size / 65536 {
                hash.update([42_u8; 65536]);
            }
            Ok(hash.finalize().into())
        })
        .await?;
    let start = Instant::now();
    let mut samples = Vec::new();
    for i in 0..3 {
        let started = Instant::now();
        let info = engine
            .reserve(&who, vault, size, digest, &format!("attachment-{i}"))
            .await?;
        engine
            .upload(&who, info, Box::pin(tokio::io::repeat(42).take(size)))
            .await?;
        engine
            .mutate(
                &who,
                vault,
                &format!("attach-{i}"),
                Mutation::Put {
                    path: format!("attachment-{i}.bin"),
                    expected: 0,
                    blob: info.key.object,
                },
            )
            .await?;
        samples.push(started.elapsed());
    }
    report(
        "large-attachment-streamed-64MiB",
        samples,
        start.elapsed(),
        3 * size,
    );
    let start = Instant::now();
    let mut samples = Vec::new();
    for _ in 0..100 {
        let started = Instant::now();
        let mut after = 0;
        loop {
            let page = engine.changes(&who, vault, after, 100).await?;
            after = page.next;
            if after == page.high_water {
                break;
            }
        }
        samples.push(started.elapsed());
    }
    report(
        "incremental-feed-203-events-page100",
        samples,
        start.elapsed(),
        0,
    );
    let blob = shared.ok_or(obsidian_sync_server::Error::Integrity)?;
    let start = Instant::now();
    let mut clients = tokio::task::JoinSet::new();
    for client in 0..8 {
        let engine = engine.clone();
        let who = who.clone();
        clients.spawn(async move {
            let mut samples = Vec::new();
            let mut expected = 0;
            for i in 0..100 {
                let started = Instant::now();
                expected = engine
                    .mutate(
                        &who,
                        vault,
                        &format!("client-{client}-{i}"),
                        Mutation::Put {
                            path: format!("client-{client}.md"),
                            expected,
                            blob,
                        },
                    )
                    .await?;
                samples.push(started.elapsed());
            }
            Ok::<_, obsidian_sync_server::Error>(samples)
        });
    }
    let mut samples = Vec::new();
    while let Some(result) = clients.join_next().await {
        samples.extend(result??);
    }
    report(
        "8-concurrent-clients-CAS-metadata",
        samples,
        start.elapsed(),
        0,
    );
    Ok(())
}
