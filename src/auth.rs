//! Local administrative credential provisioning, independent of the unknown plugin auth.
use crate::{Error, Result, db::Database};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct Identity {
    id: String,
}
impl Identity {
    pub(crate) fn id(&self) -> &str {
        &self.id
    }
}

impl Database {
    pub async fn create_vault(&self, quota: u64) -> Result<Uuid> {
        if quota == 0 || quota > i64::MAX as u64 {
            return Err(Error::Invalid);
        }
        let id = Uuid::new_v4();
        self.run(move |c| {
            c.execute(
                "INSERT INTO vaults(id,quota) VALUES(?1,?2)",
                params![id.to_string(), quota as i64],
            )?;
            Ok(id)
        })
        .await
    }
    /// Returns a high-entropy secret ONCE. Never log this value or use human passwords.
    pub async fn issue(&self, vault: Uuid, writable: bool) -> Result<(Uuid, String)> {
        let token = hex::encode(rand::random::<[u8; 32]>());
        let digest = Sha256::digest(token.as_bytes()).to_vec();
        let id = Uuid::new_v4();
        self.run(move |c| {
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "INSERT INTO principals(id,digest) VALUES(?1,?2)",
                params![id.to_string(), digest],
            )?;
            tx.execute(
                "INSERT INTO grants(principal,vault,writable) VALUES(?1,?2,?3)",
                params![id.to_string(), vault.to_string(), writable],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
        Ok((id, token))
    }
    pub async fn revoke(&self, principal: Uuid) -> Result<()> {
        self.run(move |c| {
            c.execute(
                "UPDATE principals SET revoked=1 WHERE id=?1",
                [principal.to_string()],
            )?;
            Ok(())
        })
        .await
    }
    pub async fn authenticate(&self, token: &str) -> Result<Identity> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Unauthorized);
        }
        let digest = Sha256::digest(token.as_bytes()).to_vec();
        self.run(move |c| {
            let id = c
                .query_row(
                    "SELECT id FROM principals WHERE digest=?1 AND revoked=0",
                    [digest],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Error::Unauthorized)?;
            Ok(Identity { id })
        })
        .await
    }
}
pub(crate) fn authorize(
    c: &Connection,
    identity: &Identity,
    vault: Uuid,
    write: bool,
) -> Result<()> {
    let permission: Option<bool> = c.query_row("SELECT g.writable FROM grants g JOIN principals p ON p.id=g.principal WHERE g.principal=?1 AND g.vault=?2 AND p.revoked=0", params![identity.id(),vault.to_string()], |r| r.get(0)).optional()?;
    match permission {
        Some(writable) if !write || writable => Ok(()),
        _ => Err(Error::Unauthorized),
    }
}
