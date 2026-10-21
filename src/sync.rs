//! Internal CAS model, NOT an invented Obsidian wire protocol.
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    db::Database,
    storage::{BlobInfo, BlobKey, Reader, Store},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone)]
pub struct Engine {
    pub db: Database,
    store: Store,
    uploads: Arc<Semaphore>,
    max: u64,
    timeout: Duration,
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
fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 128
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
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
        if !(1..=64).contains(&concurrency) || max == 0 || timeout.is_zero() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            db,
            store,
            uploads: Arc::new(Semaphore::new(concurrency)),
            max,
            timeout,
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
        validate_key(key)?;
        if size > self.max || size > i64::MAX as u64 {
            return Err(Error::Limit);
        }
        let hash = Sha256::digest(serde_json::to_vec(&(size, digest))?).to_vec();
        let who = who.clone();
        let key = key.to_owned();
        self.db
            .run(move |c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                authorize(&tx, &who, vault, true)?;
                if let Some(result) = replay(&tx, &who, vault, "reserve", &key, &hash)? {
                    return Ok(BlobInfo {
                        key: BlobKey {
                            vault,
                            object: result.parse().map_err(|_| Error::Integrity)?,
                        },
                        size,
                        digest,
                    });
                }
                // Charge a floor to bound zero-byte reservations and their metadata.
                let charge = size.max(4096);
                let changed = tx.execute(
                    "UPDATE vaults SET allocated=allocated+?1 WHERE id=?2 AND ?1<=quota-allocated",
                    params![charge as i64, vault.to_string()],
                )?;
                if changed != 1 {
                    return Err(Error::Limit);
                }
                let info = BlobInfo {
                    key: BlobKey::new(vault),
                    size,
                    digest,
                };
                tx.execute(
                    "INSERT INTO blobs(vault,id,size,digest) VALUES(?1,?2,?3,?4)",
                    params![
                        vault.to_string(),
                        info.key.object.to_string(),
                        size as i64,
                        digest.to_vec()
                    ],
                )?;
                record(
                    &tx,
                    &who,
                    vault,
                    "reserve",
                    &key,
                    &hash,
                    &info.key.object.to_string(),
                )?;
                tx.commit()?;
                Ok(info)
            })
            .await
    }
    pub async fn upload(&self, who: &Identity, info: BlobInfo, input: Reader) -> Result<()> {
        let _permit = self
            .uploads
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Limit)?;
        let who = who.clone();
        self.db
            .run({
                let who = who.clone();
                move |c| {
                    authorize(c, &who, info.key.vault, true)?;
                    if blob_info(c, info.key)? != info {
                        return Err(Error::Conflict);
                    }
                    Ok(())
                }
            })
            .await?;
        tokio::time::timeout(self.timeout, async {
            match self.store.put(info, input).await {
                Ok(()) | Err(Error::Conflict) => (),
                Err(e) => return Err(e),
            }
            // Also resolves publication-success/response-lost ambiguity safely.
            self.store.verify(info).await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        self.db
            .run(move |c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                authorize(&tx, &who, info.key.vault, true)?;
                tx.execute(
                    "UPDATE blobs SET ready=1 WHERE vault=?1 AND id=?2",
                    params![info.key.vault.to_string(), info.key.object.to_string()],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
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
        let who = who.clone();
        let info = self
            .db
            .run(move |c| {
                authorize(c, &who, key.vault, false)?;
                let ready: bool = c
                    .query_row(
                        "SELECT ready FROM blobs WHERE vault=?1 AND id=?2",
                        params![key.vault.to_string(), key.object.to_string()],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(false);
                if !ready {
                    return Err(Error::Conflict);
                }
                blob_info(c, key)
            })
            .await?;
        let reader = tokio::time::timeout(self.timeout, self.store.get(key))
            .await
            .map_err(|_| Error::Timeout)??;
        Ok((info, reader))
    }
}
fn uint(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    value
        .try_into()
        .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
}
pub(crate) fn blob_info(c: &Connection, key: BlobKey) -> Result<BlobInfo> {
    let (size, digest): (u64, Vec<u8>) = c
        .query_row(
            "SELECT size,digest FROM blobs WHERE vault=?1 AND id=?2",
            params![key.vault.to_string(), key.object.to_string()],
            |r| Ok((uint(r, 0)?, r.get(1)?)),
        )
        .optional()?
        .ok_or(Error::Conflict)?;
    Ok(BlobInfo {
        key,
        size,
        digest: digest.try_into().map_err(|_| Error::Integrity)?,
    })
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
pub(crate) fn replay(
    c: &Connection,
    who: &Identity,
    vault: Uuid,
    operation: &str,
    key: &str,
    hash: &[u8],
) -> Result<Option<String>> {
    let row:Option<(Vec<u8>,String)>=c.query_row("SELECT hash,result FROM replays WHERE principal=?1 AND vault=?2 AND operation=?3 AND key=?4",params![who.id(),vault.to_string(),operation,key],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    match row {
        Some((previous, result)) if previous == hash => Ok(Some(result)),
        Some(_) => Err(Error::Conflict),
        None => Ok(None),
    }
}
pub(crate) fn record(
    c: &Connection,
    who: &Identity,
    vault: Uuid,
    operation: &str,
    key: &str,
    hash: &[u8],
    result: &str,
) -> Result<()> {
    c.execute(
        "INSERT INTO replays(principal,vault,operation,key,hash,result) VALUES(?1,?2,?3,?4,?5,?6)",
        params![who.id(), vault.to_string(), operation, key, hash, result],
    )?;
    Ok(())
}
