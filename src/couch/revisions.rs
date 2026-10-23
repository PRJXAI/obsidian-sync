use super::{Couch, MAX_ANCESTRY, MAX_LEAVES, MAX_NODES, MAX_SEQUENCE};
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    storage::BlobInfo,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 1024
        || id.chars().any(char::is_control)
        || id.starts_with('_') && !id.starts_with("_design/") && !id.starts_with("_local/")
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub fn parse_revision(rev: &str) -> Result<(i64, &str)> {
    let (generation, suffix) = rev.split_once('-').ok_or(Error::Invalid)?;
    let generation = generation.parse::<i64>().map_err(|_| Error::Invalid)?;
    if !(1..=1_000_000).contains(&generation)
        || suffix.is_empty()
        || suffix.len() > 128
        || !suffix.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(Error::Invalid);
    }
    Ok((generation, suffix))
}
pub(crate) struct Incoming {
    pub id: String,
    pub rev: String,
    pub chain: Vec<String>,
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub deleted: bool,
    pub kind: Option<String>,
    pub parent: Option<String>,
}
impl Incoming {
    fn parse(mut doc: Value, new_edits: bool, max: usize) -> Result<Self> {
        let object = doc.as_object_mut().ok_or(Error::Invalid)?;
        let id = object
            .get("_id")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid)?
            .to_owned();
        validate_id(&id)?;
        if id.starts_with("_local/") {
            return Err(Error::Invalid);
        }
        if object.contains_key("_attachments") {
            return Err(Error::Unsupported);
        }
        let old = object
            .get("_rev")
            .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Invalid))
            .transpose()?;
        let deleted = object
            .get("_deleted")
            .map(|v| v.as_bool().ok_or(Error::Invalid))
            .transpose()?
            .unwrap_or(false);
        let mut chain = Vec::new();
        let parent;
        let rev = if new_edits {
            let generation = old
                .as_deref()
                .map(parse_revision)
                .transpose()?
                .map_or(1, |r| r.0 + 1);
            if generation > 1_000_000 {
                return Err(Error::Limit);
            }
            parent = old;
            let rev = format!("{generation}-{}", Uuid::new_v4().simple());
            chain.push(rev.clone());
            if let Some(ref p) = parent {
                chain.push(p.clone());
            }
            rev
        } else {
            let rev = old.ok_or(Error::Invalid)?;
            let (generation, suffix) = parse_revision(&rev)?;
            if let Some(history) = object.get("_revisions") {
                let start = history
                    .get("start")
                    .and_then(Value::as_i64)
                    .ok_or(Error::Invalid)?;
                let ids = history
                    .get("ids")
                    .and_then(Value::as_array)
                    .ok_or(Error::Invalid)?;
                if start != generation
                    || ids.is_empty()
                    || ids.len() > MAX_ANCESTRY
                    || ids.len() as i64 > start
                    || ids[0].as_str() != Some(suffix)
                {
                    return Err(Error::Invalid);
                }
                for (index, id) in ids.iter().enumerate() {
                    let id = id.as_str().ok_or(Error::Invalid)?;
                    let revision = format!("{}-{id}", start - index as i64);
                    parse_revision(&revision)?;
                    chain.push(revision);
                }
            } else {
                chain.push(rev.clone());
            }
            parent = chain.get(1).cloned();
            rev
        };
        for field in [
            "_rev",
            "_revisions",
            "_conflicts",
            "_deleted_conflicts",
            "_revs_info",
            "_revs",
        ] {
            object.remove(field);
        }
        if object
            .keys()
            .any(|k| k.starts_with('_') && !matches!(k.as_str(), "_id" | "_deleted"))
        {
            return Err(Error::Invalid);
        }
        if !deleted {
            object.remove("_deleted");
        }
        let kind = object
            .get("type")
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 64)
            .map(str::to_owned);
        let bytes = serde_json::to_vec(&doc)?;
        if bytes.len() > max {
            return Err(Error::Limit);
        }
        let digest = Sha256::digest(&bytes).into();
        Ok(Self {
            id,
            rev,
            chain,
            bytes,
            digest,
            deleted,
            kind,
            parent,
        })
    }
}
fn existing(c: &Connection, vault: Uuid, id: &str, rev: &str) -> Result<Option<BlobInfo>> {
    let row: Option<(Option<String>, Option<Vec<u8>>)> = c
        .query_row(
            "SELECT blob,digest FROM couch_revisions WHERE vault=?1 AND id=?2 AND rev=?3",
            params![vault.to_string(), id, rev],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((Some(blob), Some(hash))) => {
            let info = crate::sync::blob_info(
                c,
                crate::storage::BlobKey {
                    vault,
                    object: blob.parse().map_err(|_| Error::Integrity)?,
                },
            )?;
            if hash != info.digest {
                return Err(Error::Integrity);
            }
            Ok(Some(info))
        }
        Some((None, None)) | None => Ok(None),
        // A partially damaged reference is not an empty ancestry stub to overwrite.
        Some(_) => Err(Error::Integrity),
    }
}
/// Revalidate every edge under the publication transaction, including replayed bodies.
fn merge_history(c: &Connection, vault: Uuid, doc: &Incoming) -> Result<()> {
    for index in (0..doc.chain.len()).rev() {
        let rev = &doc.chain[index];
        let parent = doc.chain.get(index + 1);
        let (generation, _) = parse_revision(rev)?;
        let row: Option<Option<String>> = c
            .query_row(
                "SELECT parent FROM couch_revisions WHERE vault=?1 AND id=?2 AND rev=?3",
                params![vault.to_string(), doc.id, rev],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(old) = row {
            if let (Some(old), Some(new)) = (&old, parent)
                && old != new
            {
                return Err(Error::Conflict);
            }
            if old.is_none() && parent.is_some() {
                c.execute(
                    "UPDATE couch_revisions SET parent=?1 WHERE vault=?2 AND id=?3 AND rev=?4",
                    params![parent, vault.to_string(), doc.id, rev],
                )?;
            }
        } else {
            let charge = 4096_i64;
            let count: i64 = c.query_row(
                "SELECT count(*) FROM couch_revisions WHERE vault=?1 AND id=?2",
                params![vault.to_string(), doc.id],
                |r| r.get(0),
            )?;
            if count >= MAX_NODES as i64 {
                return Err(Error::Limit);
            }
            if c.execute(
                "UPDATE vaults SET allocated=allocated+?1 WHERE id=?2 AND ?1<=quota-allocated",
                params![charge, vault.to_string()],
            )? != 1
            {
                return Err(Error::Limit);
            }
            c.execute("INSERT INTO couch_revisions(vault,id,rev,generation,parent) VALUES(?1,?2,?3,?4,?5)",params![vault.to_string(),doc.id,rev,generation,parent])?;
        }
    }
    Ok(())
}
pub(crate) fn leaves(c: &Connection, vault: Uuid, id: &str) -> Result<Vec<(String, bool)>> {
    let mut statement=c.prepare("SELECT r.rev,r.deleted FROM couch_revisions r WHERE r.vault=?1 AND r.id=?2 AND r.blob IS NOT NULL AND NOT EXISTS(SELECT 1 FROM couch_revisions child WHERE child.vault=r.vault AND child.id=r.id AND child.parent=r.rev) ORDER BY r.deleted ASC,r.generation DESC,r.rev DESC")?;
    Ok(statement
        .query_map(params![vault.to_string(), id], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?)
}
impl Couch {
    pub async fn put(
        &self,
        who: &Identity,
        vault: Uuid,
        mut doc: Value,
        new_edits: bool,
    ) -> Result<Value> {
        if doc
            .get("_id")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with("_local/"))
        {
            return self.put_local(who, vault, doc).await;
        }
        if new_edits && doc.get("_rev").is_none() && doc.get("_deleted") != Some(&Value::Bool(true))
        {
            let id = doc
                .get("_id")
                .and_then(Value::as_str)
                .ok_or(Error::Invalid)?
                .to_owned();
            validate_id(&id)?;
            let identity = who.clone();
            let deleted_parent = self
                .db
                .run(move |c| {
                    authorize(c, &identity, vault, true)?;
                    let current = leaves(c, vault, &id)?;
                    Ok(current
                        .first()
                        .filter(|(_, deleted)| *deleted)
                        .map(|(rev, _)| rev.clone()))
                })
                .await?;
            if let Some(parent) = deleted_parent {
                doc["_rev"] = json!(parent);
            }
        }
        let max = self.options.max_document_bytes;
        let incoming = super::cpu()?
            .run(move || Incoming::parse(doc, new_edits, max))
            .await?;
        let identity = who.clone();
        let id = incoming.id.clone();
        let parent = incoming.parent.clone();
        let deleted = incoming.deleted;
        // Fail ordinary stale edits before doing any network I/O/quota allocation.
        if new_edits {
            self.db
                .run(move |c| {
                    authorize(c, &identity, vault, true)?;
                    check_edit(c, vault, &id, parent.as_deref(), deleted)
                })
                .await?;
        }
        let mut key_hash = Sha256::new();
        key_hash.update(serde_json::to_vec(&(
            "couch-body",
            &incoming.id,
            &incoming.rev,
            incoming.digest,
        ))?);
        let key = hex::encode(key_hash.finalize());
        let identity = who.clone();
        let id = incoming.id.clone();
        let rev = incoming.rev.clone();
        let ready = self
            .db
            .run(move |c| {
                authorize(c, &identity, vault, true)?;
                existing(c, vault, &id, &rev)
            })
            .await?;
        let info = if let Some(info) = ready {
            // CouchDB keeps the first immutable body. E2EE replays can legitimately
            // contain fresh ciphertext for this same revision; verify what is stored.
            let (_, mut reader) = self.engine.read_blob(who, info.key).await?;
            crate::storage::copy_verified(&mut reader, &mut tokio::io::sink(), info).await?;
            info
        } else {
            let info = self
                .engine
                .reserve(
                    who,
                    vault,
                    incoming.bytes.len() as u64,
                    incoming.digest,
                    &key,
                )
                .await?;
            self.engine
                .upload(
                    who,
                    info,
                    Box::pin(std::io::Cursor::new(incoming.bytes.clone())),
                )
                .await?;
            info
        };
        let who = who.clone();
        let result=self.db.run(move|c|{
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;authorize(&tx,&who,vault,true)?;
            if new_edits{check_edit(&tx,vault,&incoming.id,incoming.parent.as_deref(),incoming.deleted)?;}
            let before=leaves(&tx,vault,&incoming.id)?;
            let duplicate=existing(&tx,vault,&incoming.id,&incoming.rev)?.is_some();merge_history(&tx,vault,&incoming)?;
            if !duplicate {
                let ready:bool=tx.query_row("SELECT ready FROM blobs WHERE vault=?1 AND id=?2",params![vault.to_string(),info.key.object.to_string()],|r|r.get(0))?;
                if !ready{return Err(Error::Integrity);}
                tx.execute("UPDATE couch_revisions SET blob=?1,digest=?2,deleted=?3,kind=?4 WHERE vault=?5 AND id=?6 AND rev=?7",params![info.key.object.to_string(),incoming.digest.to_vec(),incoming.deleted,incoming.kind,vault.to_string(),incoming.id,incoming.rev])?;
            }
            let current=leaves(&tx,vault,&incoming.id)?;
            if current.is_empty()||current.len()>MAX_LEAVES{return Err(Error::Limit);}
            // History-only merges can change which branches are leaves and must refresh the feed.
            let previous:Option<String>=tx.query_row("SELECT winner FROM couch_heads WHERE vault=?1 AND id=?2",params![vault.to_string(),incoming.id],|r|r.get(0)).optional()?;
            if !duplicate||before!=current||previous.as_deref()!=Some(&current[0].0){
                if tx.execute("UPDATE couch_databases SET seq=seq+1 WHERE vault=?1 AND seq<?2",params![vault.to_string(),MAX_SEQUENCE])?!=1{return Err(Error::Limit);}
                let seq:i64=tx.query_row("SELECT seq FROM couch_databases WHERE vault=?1",[vault.to_string()],|r|r.get(0))?;
                tx.execute("INSERT INTO couch_heads(vault,id,seq,winner) VALUES(?1,?2,?3,?4) ON CONFLICT(vault,id) DO UPDATE SET seq=excluded.seq,winner=excluded.winner",params![vault.to_string(),incoming.id,seq,current[0].0])?;
            }
            tx.commit()?;Ok(json!({"ok":true,"id":incoming.id,"rev":incoming.rev}))
        }).await?;
        self.changed.notify_waiters();
        Ok(result)
    }
    pub async fn put_local(&self, who: &Identity, vault: Uuid, mut doc: Value) -> Result<Value> {
        let object = doc.as_object_mut().ok_or(Error::Invalid)?;
        let id = object
            .get("_id")
            .and_then(Value::as_str)
            .ok_or(Error::Invalid)?
            .to_owned();
        validate_id(&id)?;
        if !id.starts_with("_local/") || id.len() <= 7 {
            return Err(Error::Invalid);
        }
        let expected = object
            .remove("_rev")
            .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Invalid))
            .transpose()?;
        let deleted = object
            .get("_deleted")
            .map(|v| v.as_bool().ok_or(Error::Invalid))
            .transpose()?
            .unwrap_or(false);
        let bytes = serde_json::to_vec(&doc)?;
        if bytes.len() > 65536 {
            return Err(Error::Limit);
        }
        let who = who.clone();
        self.db.run(move|c|{
            let tx=c.transaction_with_behavior(TransactionBehavior::Immediate)?;authorize(&tx,&who,vault,true)?;
            let old:Option<(i64,i64)>=tx.query_row("SELECT revision,length(body) FROM couch_local WHERE vault=?1 AND id=?2",params![vault.to_string(),id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
            if old.map(|o|format!("0-{}",o.0))!=expected{return Err(Error::Conflict);}
            let count:i64=tx.query_row("SELECT count(*) FROM couch_local WHERE vault=?1",[vault.to_string()],|r|r.get(0))?;
            if old.is_none()&&count>=2048{return Err(Error::Limit);}
            let old_charge=old.map_or(0,|o|o.1+4096);let new_charge=if deleted{0}else{bytes.len() as i64+4096};let delta=new_charge-old_charge;
            if tx.execute("UPDATE vaults SET allocated=allocated+?1 WHERE id=?2 AND ?1<=quota-allocated",params![delta,vault.to_string()])?!=1{return Err(Error::Limit);}
            let revision=old.map_or(1,|o|o.0+1);
            if revision>MAX_SEQUENCE{return Err(Error::Limit);}
            if deleted{tx.execute("DELETE FROM couch_local WHERE vault=?1 AND id=?2",params![vault.to_string(),id])?;}
            else{tx.execute("INSERT INTO couch_local(vault,id,revision,body) VALUES(?1,?2,?3,?4) ON CONFLICT(vault,id) DO UPDATE SET revision=excluded.revision,body=excluded.body",params![vault.to_string(),id,revision,bytes])?;}
            tx.commit()?;Ok(json!({"ok":true,"id":id,"rev":format!("0-{}",if deleted{0}else{revision})}))
        }).await
    }
}
fn check_edit(
    c: &Connection,
    vault: Uuid,
    id: &str,
    parent: Option<&str>,
    deleted: bool,
) -> Result<()> {
    let current = leaves(c, vault, id)?;
    if let Some(parent) = parent {
        if !current.iter().any(|(rev, _)| rev == parent) {
            return Err(Error::Conflict);
        }
    } else if deleted {
        return Err(Error::NotFound);
    } else if !current.is_empty() {
        return Err(Error::Conflict);
    }
    Ok(())
}
