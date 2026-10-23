#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use obsidian_sync_server::{
    Error, Result,
    config::Config,
    couch::Couch,
    db::Database,
    jobs::Queue,
    storage::{BlockingPool, Store},
    transport,
};
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    version,
    about = "Private Self-hosted LiveSync-compatible replication service."
)]
struct Args {
    #[arg(
        long,
        env = "SYNC_CONFIG",
        default_value = "/etc/obsidian-sync/config.toml"
    )]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Serve,
    CheckConfig,
    VerifyStorage,
    CreateVault,
    CreateDatabase {
        #[arg(long)]
        name: String,
    },
    ListDatabases,
    Issue {
        #[arg(long)]
        vault: Uuid,
        #[arg(long)]
        read_only: bool,
        #[arg(long, conflicts_with = "read_only")]
        allow_database_reset: bool,
    },
    Revoke {
        #[arg(long)]
        principal: Uuid,
    },
    EnqueueIntegrity {
        #[arg(long)]
        vault: Uuid,
        #[arg(long)]
        credential_file: PathBuf,
        #[arg(long)]
        request_id: String,
    },
    JobStatus {
        #[arg(long)]
        job: Uuid,
        #[arg(long)]
        credential_file: PathBuf,
    },
    Backup {
        #[arg(long)]
        destination: PathBuf,
    },
    Checkpoint,
}
fn main() {
    tracing_subscriber::fmt()
        .json()
        // Fixed first-party-only filter: dependency diagnostics may include signed URLs.
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "obsidian_sync_server=info",
        ))
        .init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(8)
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("runtime initialization failed");
            std::process::exit(1);
        }
    };
    if let Err(error) = runtime.block_on(run(Args::parse())) {
        tracing::error!(kind=%error,"operation failed");
        std::process::exit(1);
    }
}
async fn run(args: Args) -> Result<()> {
    let config = Config::load(&args.config).await?;
    if matches!(args.command, Command::CheckConfig) {
        println!("configuration valid; Self-hosted LiveSync CouchDB adapter enabled");
        return Ok(());
    }
    let pool = BlockingPool::new(4)?;
    let db = Database::open(&config.metadata_dir, pool.clone()).await?;
    let queue = Queue::new(
        db.clone(),
        config.job_quota_per_vault,
        config.job_max_attempts,
    )?;
    match args.command {
        Command::CheckConfig => (),
        Command::VerifyStorage => {
            Store::open(
                &config.storage,
                pool,
                config.max_blob_bytes,
                config.operation_timeout_secs,
            )
            .await?;
            println!("storage capability probe passed");
        }
        Command::CreateVault => println!("{}", db.create_vault(config.vault_quota_bytes).await?),
        Command::CreateDatabase { name } => println!(
            "{}",
            db.create_database(&name, config.vault_quota_bytes).await?
        ),
        Command::ListDatabases => {
            for (name, vault, active) in db.databases().await? {
                println!("database={name} vault={vault} active={active}");
            }
        }
        Command::Issue {
            vault,
            read_only,
            allow_database_reset,
        } => {
            let (id, token) = db.issue(vault, !read_only).await?;
            if allow_database_reset {
                db.allow_database_reset(id, vault).await?;
            }
            // Explicit CLI secret output, never tracing. Protect/redirection belongs to operator.
            println!("principal={id}\ntoken={token}");
        }
        Command::Revoke { principal } => db.revoke(principal).await?,
        Command::EnqueueIntegrity {
            vault,
            credential_file,
            request_id,
        } => {
            let who = identity(&db, credential_file).await?;
            println!("{}", queue.enqueue(&who, vault, &request_id).await?);
        }
        Command::JobStatus {
            job,
            credential_file,
        } => {
            let who = identity(&db, credential_file).await?;
            let status = queue.status(&who, job).await?;
            println!("state={} attempts={}", status.state, status.attempts);
        }
        Command::Backup { destination } => db.backup(destination).await?,
        Command::Checkpoint => db.checkpoint().await?,
        Command::Serve => {
            let store = Store::open(
                &config.storage,
                pool,
                config.max_blob_bytes,
                config.operation_timeout_secs,
            )
            .await?;
            let (tx, rx) = tokio::sync::watch::channel(false);
            let couch = Couch::new(db.clone(), store.clone(), &config, rx.clone())?;
            let app = obsidian_sync_server::couch::http::router(couch)?;
            let mut worker = tokio::spawn(queue.worker(
                store,
                Duration::from_secs(config.operation_timeout_secs),
                rx,
            ));
            tracing::info!("started Self-hosted LiveSync replication adapter");
            let shutdown_tx = tx.clone();
            let server = transport::serve(config.listen, app, async move {
                shutdown_signal().await;
                let _ = shutdown_tx.send(true);
            });
            tokio::pin!(server);
            // A worker completing AFTER shutdown is normal, not an operational failure.
            let worker_done = tokio::select! {
                result=&mut server=>{result?;false}
                result=&mut worker=>{
                    result??;
                    if !*tx.borrow() {return Err(Error::Backend);}
                    tokio::time::timeout(Duration::from_secs(30),&mut server).await.map_err(|_|Error::Timeout)??;
                    true
                }
            };
            let _ = tx.send(true);
            if !worker_done {
                worker.await??;
            }
            db.checkpoint().await?;
            tracing::info!("shutdown complete");
        }
    }
    Ok(())
}
async fn identity(db: &Database, path: PathBuf) -> Result<obsidian_sync_server::auth::Identity> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await?;
    let mut bytes = Vec::new();
    file.take(129).read_to_end(&mut bytes).await?;
    if bytes.len() > 128 {
        return Err(Error::Invalid);
    }
    db.authenticate(
        std::str::from_utf8(&bytes)
            .map_err(|_| Error::Unauthorized)?
            .trim(),
    )
    .await
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term) => tokio::select! {_=tokio::signal::ctrl_c()=>(),_=term.recv()=>()},
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
