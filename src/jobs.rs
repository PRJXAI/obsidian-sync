//! Bounded, persisted, at-least-once read-only integrity jobs.
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    db::Database,
    storage::{BlobKey, Store},
    sync::{blob_info, record, replay},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Clone)]
pub struct Queue {
    db: Database,
    quota: u32,
    max_attempts: u32,
}
#[derive(Debug)]
pub struct Claim {
    pub id: Uuid,
    pub vault: Uuid,
    owner: Uuid,
    pub attempts: u32,
}
#[derive(Debug)]
pub struct Status {
    pub state: String,
    pub attempts: u32,
}
fn now() -> Result<i64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_secs()
        .try_into()
        .map_err(|_| Error::Invalid)
}
pub fn backoff(attempt: u32, jitter: u64) -> u64 {
    (1_u64 << attempt.min(8)).min(256) + jitter % 30
}
impl Queue {
    pub fn new(db: Database, quota: u32, max_attempts: u32) -> Result<Self> {
        if !(1..=1000).contains(&quota) || !(1..=10).contains(&max_attempts) {
            return Err(Error::Invalid);
        }
        Ok(Self {
            db,
            quota,
            max_attempts,
        })
    }
    pub async fn enqueue(&self, who: &Identity, vault: Uuid, key: &str) -> Result<Uuid> {
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        {
            return Err(Error::Invalid);
        }
        let who = who.clone();
        let key = key.to_owned();
        let quota = self.quota;
        self.db
            .run(move |c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                authorize(&tx, &who, vault, true)?;
                if let Some(id) = replay(&tx, &who, vault, "integrity-job", &key, b"integrity-v1")?
                {
                    return id.parse().map_err(|_| Error::Integrity);
                }
                // Include terminal records: bounded metadata, not merely a bounded pending queue.
                let count: u32 = tx.query_row(
                    "SELECT count(*) FROM jobs WHERE vault=?1",
                    [vault.to_string()],
                    |r| r.get(0),
                )?;
                if count >= quota {
                    return Err(Error::Limit);
                }
                let id = Uuid::new_v4();
                tx.execute(
                    "INSERT INTO jobs(id,vault,state) VALUES(?1,?2,'queued')",
                    params![id.to_string(), vault.to_string()],
                )?;
                record(
                    &tx,
                    &who,
                    vault,
                    "integrity-job",
                    &key,
                    b"integrity-v1",
                    &id.to_string(),
                )?;
                tx.commit()?;
                Ok(id)
            })
            .await
    }
    pub async fn status(&self, who: &Identity, id: Uuid) -> Result<Status> {
        let who = who.clone();
        self.db
            .run(move |c| {
                let row: Option<(String, String, u32)> = c
                    .query_row(
                        "SELECT vault,state,attempts FROM jobs WHERE id=?1",
                        [id.to_string()],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )
                    .optional()?;
                let (vault, state, attempts) = row.ok_or(Error::Unauthorized)?;
                authorize(c, &who, vault.parse().map_err(|_| Error::Integrity)?, false)?;
                Ok(Status { state, attempts })
            })
            .await
    }
    pub async fn claim(&self) -> Result<Option<Claim>> {
        let max = self.max_attempts;
        let now = now()?;
        self.db.run(move|c|{
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute("UPDATE jobs SET state='failed',owner=NULL WHERE state='queued' AND attempts>=?1",[max])?;
            let row:Option<(String,String,u32)>=tx.query_row("SELECT j.id,j.vault,j.attempts FROM jobs j JOIN vaults v ON v.id=j.vault WHERE j.state='queued' AND j.available<=?1 ORDER BY v.last_claim,j.available,j.id LIMIT 1",[now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let Some((id,vault,attempts))=row else{return Ok(None);};
            let claim=Claim{id:id.parse().map_err(|_|Error::Integrity)?,vault:vault.parse().map_err(|_|Error::Integrity)?,owner:Uuid::new_v4(),attempts:attempts+1};
            tx.execute("UPDATE jobs SET state='running',owner=?1,attempts=attempts+1,claimed=?2 WHERE id=?3 AND state='queued'",params![claim.owner.to_string(),now,id])?;
            tx.execute("UPDATE vaults SET last_claim=(SELECT coalesce(max(last_claim),0)+1 FROM vaults) WHERE id=?1",[vault])?;
            tx.commit()?;Ok(Some(claim))
        }).await
    }
    pub async fn complete(&self, claim: Claim, success: bool) -> Result<()> {
        let max = self.max_attempts;
        let available = now()? + backoff(claim.attempts, rand::random()) as i64;
        self.db.run(move|c|{
            let state=if success{"done"}else if claim.attempts>=max{"failed"}else{"queued"};
            let changed=c.execute("UPDATE jobs SET state=?1,owner=NULL,available=?2 WHERE id=?3 AND state='running' AND owner=?4",params![state,available,claim.id.to_string(),claim.owner.to_string()])?;
            if changed!=1{return Err(Error::Conflict);}Ok(())
        }).await
    }
    async fn inspect(&self, claim: &Claim, store: &Store, timeout: Duration) -> Result<()> {
        let mut after = String::new();
        loop {
            let vault = claim.vault;
            let cursor = after.clone();
            let batch=self.db.run(move|c|{
                let mut stmt=c.prepare("SELECT id FROM blobs WHERE vault=?1 AND ready=1 AND id>?2 ORDER BY id LIMIT 64")?;
                let ids=stmt.query_map(params![vault.to_string(),cursor],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
                ids.into_iter().map(|id|{let key=BlobKey{vault,object:id.parse().map_err(|_|Error::Integrity)?};blob_info(c,key)}).collect::<Result<Vec<_>>>()
            }).await?;
            if batch.is_empty() {
                return Ok(());
            }
            for info in batch {
                after = info.key.object.to_string();
                tokio::time::timeout(timeout, store.verify(info))
                    .await
                    .map_err(|_| Error::Timeout)??;
            }
        }
    }
    pub async fn worker(
        self,
        store: Store,
        timeout: Duration,
        mut stop: watch::Receiver<bool>,
    ) -> Result<()> {
        loop {
            if *stop.borrow() {
                break;
            }
            let claim = self.claim().await?;
            if let Some(claim) = claim {
                let result = tokio::select! {
                    result=tokio::time::timeout(Duration::from_secs(3600),self.inspect(&claim,&store,timeout))=>matches!(result,Ok(Ok(()))),
                    _=stop.changed()=>break,
                };
                self.complete(claim, result).await?;
            } else {
                tokio::select! {_=tokio::time::sleep(Duration::from_secs(1))=>(),_=stop.changed()=>break}
            }
        }
        Ok(())
    }
}
