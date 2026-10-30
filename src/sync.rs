//! Internal CAS model, NOT an invented Obsidian wire protocol.
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    blob::BlobPublisher,
    db::{Database, uint},
    replay::{record, replay, validate_key},
    storage::{BlobInfo, BlobKey, Reader, Store},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct Engine {
    pub db: Database,
    blobs: BlobPublisher,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Mutation {
    Put {
        path: String,
        expected: u64,
        blob: Uuid,
    },
    Delete {
        path: String,
        expected: u64,
    },
    Rename {
        from: String,
        expected: u64,
        to: String,
        target_expected: u64,
    },
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub revision: u64,
    pub path: String,
    pub blob: Option<Uuid>,
}
#[derive(Debug)]
pub struct Page {
    pub high_water: u64,
    pub next: u64,
    pub changes: Vec<Change>,
}

pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == ".." || s.len() > 255)
        || path.starts_with('~')
        || path.contains(':')
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
impl Engine {
    pub fn new(
        db: Database,
        store: Store,
        concurrency: usize,
        max: u64,
        timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            db,
            blobs: BlobPublisher::new(store, concurrency, max, timeout)?,
        })
    }
    pub async fn reserve(
        &self,
        who: &Identity,
        vault: Uuid,
        size: u64,
        digest: [u8; 32],
        key: &str,
    ) -> Result<BlobInfo> {
        self.blobs
            .reserve(&self.db, who, vault, size, digest, key)
            .await
    }
    pub async fn upload(&self, who: &Identity, info: BlobInfo, input: Reader) -> Result<()> {
        self.blobs.upload(&self.db, who, info, input).await
    }
    pub async fn mutate(
        &self,
        who: &Identity,
        vault: Uuid,
        key: &str,
        mutation: Mutation,
    ) -> Result<u64> {
        validate_key(key)?;
        match &mutation {
            Mutation::Put { path, .. } | Mutation::Delete { path, .. } => validate_path(path)?,
            Mutation::Rename { from, to, .. } => {
                validate_path(from)?;
                validate_path(to)?;
                if from == to {
                    return Err(Error::Invalid);
                }
            }
        }
        let hash = Sha256::digest(serde_json::to_vec(&mutation)?).to_vec();
        let operation = match &mutation {
            Mutation::Put { .. } => "put",
            Mutation::Delete { .. } => "delete",
            Mutation::Rename { .. } => "rename",
        };
        let who = who.clone();
        let key = key.to_owned();
        self.db
            .run(move |c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                authorize(&tx, &who, vault, true)?;
                if let Some(result) = replay(&tx, &who, vault, operation, &key, &hash)? {
                    return result.parse().map_err(|_| Error::Integrity);
                }
                let revision = match mutation {
                    Mutation::Put {
                        path,
                        expected,
                        blob,
                    } => {
                        check(&tx, vault, &path, expected)?;
                        let ready: bool = tx
                            .query_row(
                                "SELECT ready FROM blobs WHERE vault=?1 AND id=?2",
                                params![vault.to_string(), blob.to_string()],
                                |r| r.get(0),
                            )
                            .optional()?
                            .unwrap_or(false);
                        if !ready {
                            return Err(Error::Conflict);
                        }
                        publish(&tx, vault, &path, Some(blob))?
                    }
                    Mutation::Delete { path, expected } => {
                        check(&tx, vault, &path, expected)?;
                        publish(&tx, vault, &path, None)?
                    }
                    Mutation::Rename {
                        from,
                        expected,
                        to,
                        target_expected,
                    } => {
                        let source = check(&tx, vault, &from, expected)?.ok_or(Error::Conflict)?;
                        if check(&tx, vault, &to, target_expected)?.is_some() {
                            return Err(Error::Conflict);
                        }
                        publish(&tx, vault, &from, None)?;
                        publish(&tx, vault, &to, Some(source))?
                    }
                };
                record(
                    &tx,
                    &who,
                    vault,
                    operation,
                    &key,
                    &hash,
                    &revision.to_string(),
                )?;
                tx.commit()?;
                Ok(revision)
            })
            .await
    }
    pub async fn changes(
        &self,
        who: &Identity,
        vault: Uuid,
        after: u64,
        limit: u32,
    ) -> Result<Page> {
        if limit == 0 || limit > 1000 || after > i64::MAX as u64 {
            return Err(Error::Invalid);
        }
        let who = who.clone();
        self.db.run(move|c|{
            let tx=c.transaction()?;
            authorize(&tx,&who,vault,false)?;
            let high_water:u64=tx.query_row("SELECT revision FROM vaults WHERE id=?1",[vault.to_string()],|r|uint(r,0))?;
            if after>high_water{return Err(Error::Conflict);}
            let mut stmt=tx.prepare("SELECT revision,path,blob FROM changes WHERE vault=?1 AND revision>?2 ORDER BY revision LIMIT ?3")?;
            let changes=stmt.query_map(params![vault.to_string(),after as i64,limit],|r|{
                let blob:Option<String>=r.get(2)?;
                Ok((uint(r,0)?,r.get::<_,String>(1)?,blob))
            })?.map(|row|{let(revision,path,blob)=row?;Ok(Change{revision,path,blob:blob.map(|s|s.parse().map_err(|_|Error::Integrity)).transpose()?})}).collect::<Result<Vec<_>>>()?;
            let next=changes.last().map_or(after,|c|c.revision);
            Ok(Page{high_water,next,changes})
        }).await
    }
    pub async fn read_blob(&self, who: &Identity, key: BlobKey) -> Result<(BlobInfo, Reader)> {
        self.blobs.read_blob(&self.db, who, key).await
    }
}
fn check(c: &Connection, vault: Uuid, path: &str, expected: u64) -> Result<Option<Uuid>> {
    let head: Option<(u64, Option<String>)> = c
        .query_row(
            "SELECT revision,blob FROM heads WHERE vault=?1 AND path=?2",
            params![vault.to_string(), path],
            |r| Ok((uint(r, 0)?, r.get(1)?)),
        )
        .optional()?;
    if head.as_ref().map_or(0, |h| h.0) != expected {
        return Err(Error::Conflict);
    }
    head.and_then(|h| h.1)
        .map(|b| b.parse().map_err(|_| Error::Integrity))
        .transpose()
}
fn publish(c: &Connection, vault: Uuid, path: &str, blob: Option<Uuid>) -> Result<u64> {
    c.execute(
        "UPDATE vaults SET revision=revision+1 WHERE id=?1 AND revision<100000",
        [vault.to_string()],
    )?;
    if c.changes() != 1 {
        return Err(Error::Limit);
    }
    let revision: u64 = c.query_row(
        "SELECT revision FROM vaults WHERE id=?1",
        [vault.to_string()],
        |r| uint(r, 0),
    )?;
    let blob = blob.map(|b| b.to_string());
    c.execute("INSERT INTO heads(vault,path,revision,blob) VALUES(?1,?2,?3,?4) ON CONFLICT(vault,path) DO UPDATE SET revision=excluded.revision,blob=excluded.blob",params![vault.to_string(),path,revision as i64,blob])?;
    c.execute(
        "INSERT INTO changes(vault,revision,path,blob) VALUES(?1,?2,?3,?4)",
        params![vault.to_string(), revision as i64, path, blob],
    )?;
    Ok(revision)
}
