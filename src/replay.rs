//! Payload-bound request replay for blob reservations, internal CAS and integrity jobs.
//! Couch imported revision identities deliberately have different first-body-wins semantics.
use crate::{Error, Result, auth::Identity};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

pub(crate) fn validate_key(key: &str) -> Result<()> {
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

/// The caller must authorize inside the same transaction before consulting replay state.
pub(crate) fn replay(
    c: &Connection,
    who: &Identity,
    vault: Uuid,
    operation: &str,
    key: &str,
    hash: &[u8],
) -> Result<Option<String>> {
    let row: Option<(Vec<u8>, String)> = c.query_row(
        "SELECT hash,result FROM replays WHERE principal=?1 AND vault=?2 AND operation=?3 AND key=?4",
        params![who.id(), vault.to_string(), operation, key],
        |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?;
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
