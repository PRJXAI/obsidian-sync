//! Shared durable blob publication, independent of legacy CAS and Couch revision semantics.
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    db::{Database, uint},
    replay::{record, replay, validate_key},
    storage::{BlobInfo, BlobKey, Reader, Store},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Clones share admission; callers supply their current metadata authority.
#[derive(Clone)]
pub(crate) struct BlobPublisher {
    store: Store,
    uploads: Arc<Semaphore>,
    max: u64,
    timeout: Duration,
}
impl BlobPublisher {
    pub(crate) fn new(
        store: Store,
        concurrency: usize,
        max: u64,
        timeout: Duration,
    ) -> Result<Self> {
        if !(1..=64).contains(&concurrency) || max == 0 || timeout.is_zero() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            uploads: Arc::new(Semaphore::new(concurrency)),
            max,
            timeout,
        })
    }
    pub(crate) async fn reserve(
        &self,
        db: &Database,
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
        db.run(move |c| {
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
    pub(crate) async fn upload(
        &self,
        db: &Database,
        who: &Identity,
        info: BlobInfo,
        input: Reader,
    ) -> Result<()> {
        // HTTP execution admission bounds waiters; a busy upload is backpressure,
        // not storage exhaustion. Preserve one deadline across admission and I/O.
        let deadline = tokio::time::Instant::now() + self.timeout;
        let _permit = tokio::time::timeout_at(deadline, self.uploads.clone().acquire_owned())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Backend)?;
        let who = who.clone();
        db.run({
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
        tokio::time::timeout_at(deadline, async {
            match self.store.put(info, input).await {
                Ok(()) | Err(Error::Conflict) => (),
                Err(e) => return Err(e),
            }
            // Also resolves publication-success/response-lost ambiguity safely.
            self.store.verify(info).await
        })
        .await
        .map_err(|_| Error::Timeout)??;
        db.run(move |c| {
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
    pub(crate) async fn read_blob(
        &self,
        db: &Database,
        who: &Identity,
        key: BlobKey,
    ) -> Result<(BlobInfo, Reader)> {
        let who = who.clone();
        let info = db
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
