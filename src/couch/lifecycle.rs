//! Explicit per-database bootstrap reset capability; never physical history destruction.
use super::Couch;
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    db::Database,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use uuid::Uuid;
fn manager(c: &Connection, who: &Identity, vault: Uuid) -> Result<()> {
    authorize(c, who, vault, true)?;
    let allowed: bool = c.query_row(
        "SELECT EXISTS(SELECT 1 FROM couch_managers WHERE principal=?1 AND vault=?2)",
        params![who.id(), vault.to_string()],
        |r| r.get(0),
    )?;
    if allowed {
        Ok(())
    } else {
        Err(Error::Unauthorized)
    }
}
impl Database {
    pub async fn databases(&self) -> Result<Vec<(String, Uuid, bool)>> {
        self.run(|c| {
            let mut stmt =
                c.prepare("SELECT name,vault,active FROM couch_databases ORDER BY name")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, bool>(2)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            rows.into_iter()
                .map(|(name, vault, active)| {
                    Ok((name, vault.parse().map_err(|_| Error::Integrity)?, active))
                })
                .collect()
        })
        .await
    }
    /// Local trusted administration, not a client-controlled privilege escalation.
    pub async fn allow_database_reset(&self, principal: Uuid, vault: Uuid) -> Result<()> {
        self.run(move |c| {
            let write: Option<bool> = c
                .query_row(
                    "SELECT writable FROM grants WHERE principal=?1 AND vault=?2",
                    params![principal.to_string(), vault.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if write != Some(true) {
                return Err(Error::Unauthorized);
            }
            c.execute(
                "INSERT OR IGNORE INTO couch_managers(principal,vault) VALUES(?1,?2)",
                params![principal.to_string(), vault.to_string()],
            )?;
            Ok(())
        })
        .await
    }
}
impl Couch {
    pub async fn reset(&self, who: &Identity, name: &str, vault: Uuid) -> Result<()> {
        let who = who.clone();
        let name = name.to_owned();
        self.db.run(move|c|{
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;manager(&tx,&who,vault)?;
            let seq:Option<i64>=tx.query_row("SELECT seq FROM couch_databases WHERE name=?1 AND vault=?2 AND active=1",params![name,vault.to_string()],|r|r.get(0)).optional()?;
            let seq=seq.ok_or(Error::NotFound)?;
            let generations:i64=tx.query_row("SELECT count(*) FROM couch_archives WHERE name=?1",[&name],|r|r.get(0))?;if generations>=16{return Err(Error::Limit);}
            let(quota,used):(i64,i64)=tx.query_row("SELECT quota,allocated FROM vaults WHERE id=?1",[vault.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let grants:i64=tx.query_row("SELECT count(*) FROM grants WHERE vault=?1",[vault.to_string()],|r|r.get(0))?;
            let charge=4096+grants*4096;
            if charge>quota-used{return Err(Error::Limit);}
            let next=Uuid::new_v4().to_string();
            tx.execute("INSERT INTO vaults(id,quota,allocated) VALUES(?1,?2,?3)",params![next,quota,used+charge])?;
            tx.execute("INSERT INTO grants(principal,vault,writable) SELECT principal,?1,writable FROM grants WHERE vault=?2",params![next,vault.to_string()])?;
            tx.execute("INSERT INTO couch_managers(principal,vault) SELECT principal,?1 FROM couch_managers WHERE vault=?2",params![next,vault.to_string()])?;
            tx.execute("INSERT INTO couch_archive_grants(principal,vault,writable) SELECT principal,vault,writable FROM grants WHERE vault=?1",[vault.to_string()])?;
            // Fence all in-flight old-generation uploads/reads. Already reserved bytes are
            // included in inherited allocation; no late old-generation reservation can commit.
            tx.execute("DELETE FROM grants WHERE vault=?1",[vault.to_string()])?;
            tx.execute("INSERT INTO couch_archives(vault,name,seq) VALUES(?1,?2,?3)",params![vault.to_string(),name,seq])?;
            tx.execute("UPDATE couch_databases SET vault=?1,seq=0,active=0 WHERE name=?2 AND vault=?3",params![next,name,vault.to_string()])?;
            tx.commit()?;Ok(())
        }).await?;
        self.changed.notify_waiters();
        Ok(())
    }
    pub async fn activate(&self, who: &Identity, name: &str, vault: Uuid) -> Result<bool> {
        let who = who.clone();
        let name = name.to_owned();
        self.db
            .run(move |c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                manager(&tx, &who, vault)?;
                let active: Option<bool> = tx
                    .query_row(
                        "SELECT active FROM couch_databases WHERE name=?1 AND vault=?2",
                        params![name, vault.to_string()],
                        |r| r.get(0),
                    )
                    .optional()?;
                let active = active.ok_or(Error::Conflict)?;
                if !active {
                    tx.execute(
                        "UPDATE couch_databases SET active=1 WHERE name=?1 AND vault=?2",
                        params![name, vault.to_string()],
                    )?;
                }
                tx.commit()?;
                Ok(!active)
            })
            .await
    }
}
pub fn sequence(vault: Uuid, counter: i64) -> String {
    format!("{counter}-{vault}")
}
pub fn parse_sequence(vault: Uuid, cursor: &str) -> Result<i64> {
    if cursor == "0" {
        return Ok(0);
    }
    let (counter, generation) = cursor.split_once('-').ok_or(Error::Invalid)?;
    if generation != vault.to_string() {
        return Err(Error::Invalid);
    }
    let counter = counter.parse::<i64>().map_err(|_| Error::Invalid)?;
    if !(0..=super::MAX_SEQUENCE).contains(&counter) {
        return Err(Error::Invalid);
    }
    Ok(counter)
}
