//! Self-hosted LiveSync's PouchDB/CouchDB document protocol, not a file REST API.
pub mod http;
mod json;
mod lifecycle;
pub use lifecycle::{parse_sequence, sequence};
mod reads;
mod revisions;
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    blob::BlobPublisher,
    db::Database,
    storage::Store,
};
pub use revisions::{parse_revision, validate_id};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Notify, watch};
use uuid::Uuid;

// Shared, explicitly bounded CPU pool. Permits remain owned by canceled blocking tasks.
static CPU: std::sync::OnceLock<crate::storage::BlockingPool> = std::sync::OnceLock::new();
pub(crate) fn cpu() -> Result<crate::storage::BlockingPool> {
    if CPU.get().is_none() {
        let _ = CPU.set(crate::storage::BlockingPool::new(2)?);
    }
    CPU.get().cloned().ok_or(Error::Backend)
}
pub(crate) async fn measured(value: Value) -> Result<(usize, usize, Value)> {
    cpu()?
        .run(move || {
            let heap = json::footprint(&value)?;
            Ok((serde_json::to_vec(&value)?.len(), heap, value))
        })
        .await
}

pub const MAX_NODES: usize = 10000;
pub const MAX_ANCESTRY: usize = 1000;
pub const MAX_LEAVES: usize = 128;
pub const MAX_SEQUENCE: i64 = 1000000;
#[derive(Clone)]
pub struct Couch {
    pub(crate) db: Database,
    pub(crate) blobs: BlobPublisher,
    pub(crate) options: crate::config::HttpConfig,
    pub(crate) changed: Arc<Notify>,
    pub(crate) stop: watch::Receiver<bool>,
}
impl Couch {
    pub fn new(
        db: Database,
        store: Store,
        config: &crate::config::Config,
        stop: watch::Receiver<bool>,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            blobs: BlobPublisher::new(
                store,
                config.max_inflight,
                config.max_blob_bytes,
                Duration::from_secs(config.operation_timeout_secs),
            )?,
            db,
            options: config.http.clone(),
            changed: Arc::new(Notify::new()),
            stop,
        })
    }
    pub async fn resolve(&self, who: &Identity, name: &str, write: bool) -> Result<Uuid> {
        let (vault, active) = self.resolve_entry(who, name, write).await?;
        if active {
            Ok(vault)
        } else {
            Err(Error::NotFound)
        }
    }
    pub async fn resolve_entry(
        &self,
        who: &Identity,
        name: &str,
        write: bool,
    ) -> Result<(Uuid, bool)> {
        validate_database(name)?;
        let who = who.clone();
        let name = name.to_owned();
        self.db
            .run(move |c| {
                let tx = c.transaction()?;
                let entry: Option<(String, bool)> = tx
                    .query_row(
                        "SELECT vault,active FROM couch_databases WHERE name=?1",
                        [name],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let (vault, active) = entry.ok_or(Error::Unauthorized)?;
                let vault: Uuid = vault.parse().map_err(|_| Error::Integrity)?;
                authorize(&tx, &who, vault, write)?;
                Ok((vault, active))
            })
            .await
    }
    pub async fn instance(&self) -> Result<String> {
        self.db
            .run(|c| {
                Ok(c.query_row(
                    "SELECT value FROM server_meta WHERE key='instance'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
    }
    pub async fn info(&self, who: &Identity, name: &str, vault: Uuid) -> Result<Value> {
        let who = who.clone();
        let name = name.to_owned();
        self.db.run(move|c|{
            let tx=c.transaction()?;authorize(&tx,&who,vault,false)?;
            let seq:i64=tx.query_row("SELECT seq FROM couch_databases WHERE vault=?1",[vault.to_string()],|r|r.get(0))?;
            let (count,deleted):(i64,i64)=tx.query_row("SELECT coalesce(sum(NOT r.deleted),0),coalesce(sum(r.deleted),0) FROM couch_heads h JOIN couch_revisions r ON r.vault=h.vault AND r.id=h.id AND r.rev=h.winner WHERE h.vault=?1",[vault.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            Ok(json!({"db_name":name,"doc_count":count,"doc_del_count":deleted,"update_seq":seq,"purge_seq":0,"compact_running":false,"instance_start_time":"0","uuid":vault.to_string()}))
        }).await
    }
}
impl Database {
    /// Local administration only: a database alias is never created by an anonymous HTTP PUT.
    pub async fn create_database(&self, name: &str, quota: u64) -> Result<Uuid> {
        validate_database(name)?;
        if quota < 4096 || quota > i64::MAX as u64 {
            return Err(Error::Invalid);
        }
        let name = name.to_owned();
        let id = Uuid::new_v4();
        self.run(move |c| {
            let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            if tx
                .query_row(
                    "SELECT 1 FROM couch_databases WHERE name=?1",
                    [&name],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .is_some()
            {
                return Err(Error::Conflict);
            }
            tx.execute(
                "INSERT INTO vaults(id,quota) VALUES(?1,?2)",
                params![id.to_string(), quota as i64],
            )?;
            tx.execute(
                "INSERT INTO couch_databases(name,vault) VALUES(?1,?2)",
                params![name, id.to_string()],
            )?;
            tx.commit()?;
            Ok(id)
        })
        .await
    }
}
pub fn validate_database(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "health"
        || name.len() > 80
        || !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_$()+-".contains(&b))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
