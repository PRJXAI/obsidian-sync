#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use obsidian_sync_server::{
    Error, Result,
    config::Config,
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
    about = "Private sync persistence service. Client protocol not yet configured."
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
    Issue {
        #[arg(long)]
        vault: Uuid,
        #[arg(long)]
        read_only: bool,
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
        println!("configuration valid; plugin protocol NOT configured");
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
        Command::Issue { vault, read_only } => {
            let (id, token) = db.issue(vault, !read_only).await?;
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
            let mut worker = tokio::spawn(queue.worker(
                store,
                Duration::from_secs(config.operation_timeout_secs),
                rx,
            ));
            tracing::info!("started; client protocol unavailable; readiness remains false");
            // Worker failure is fatal, not a silently degraded background task.
            tokio::select! {
                result=transport::serve(config.listen,shutdown_signal())=>{result?;}
                result=&mut worker=>{result??;return Err(Error::Backend);}
            }
            let _ = tx.send(true);
            worker.await??;
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
