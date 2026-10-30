use super::{
    Couch, MAX_ANCESTRY,
    revisions::{leaves, parse_revision, validate_id},
};
use crate::{
    Error, Result,
    auth::{Identity, authorize},
    storage::{BlobInfo, BlobKey},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct ReadOptions {
    pub rev: Option<String>,
    pub latest: bool,
    pub revs: bool,
    pub conflicts: bool,
    pub revs_info: bool,
    pub deleted_conflicts: bool,
    pub all_leaves: bool,
}
fn descendants(c: &Connection, vault: Uuid, id: &str, rev: &str) -> Result<Vec<String>> {
    parse_revision(rev)?;
    let mut stmt=c.prepare("WITH RECURSIVE tree(rev) AS (SELECT rev FROM couch_revisions WHERE vault=?1 AND id=?2 AND rev=?3 UNION ALL SELECT r.rev FROM couch_revisions r JOIN tree t ON r.parent=t.rev WHERE r.vault=?1 AND r.id=?2) SELECT r.rev FROM couch_revisions r JOIN tree t ON t.rev=r.rev WHERE r.vault=?1 AND r.id=?2 AND r.blob IS NOT NULL AND NOT EXISTS(SELECT 1 FROM couch_revisions child WHERE child.vault=r.vault AND child.id=r.id AND child.parent=r.rev) ORDER BY r.deleted ASC,r.generation DESC,r.rev DESC")?;
    Ok(stmt
        .query_map(params![vault.to_string(), id, rev], |r| r.get(0))?
        .collect::<std::result::Result<_, _>>()?)
}

struct ReadPlan {
    info: BlobInfo,
    rev: String,
    history: Vec<(String, bool)>,
    conflicts: Vec<String>,
    deleted_conflicts: Vec<String>,
}
fn plan(c: &Connection, vault: Uuid, id: &str, options: &ReadOptions) -> Result<ReadPlan> {
    let current = leaves(c, vault, id)?;
    let rev = match &options.rev {
        Some(rev) => {
            parse_revision(rev)?;
            if options.latest {
                descendants(c, vault, id, rev)?
                    .into_iter()
                    .next()
                    .ok_or(Error::NotFound)?
            } else {
                rev.clone()
            }
        }
        None => {
            let first = current.first().ok_or(Error::NotFound)?;
            if first.1 {
                return Err(Error::NotFound);
            }
            first.0.clone()
        }
    };
    let row: Option<(Option<String>, Option<Vec<u8>>, bool)> = c
        .query_row(
            "SELECT blob,digest,deleted FROM couch_revisions WHERE vault=?1 AND id=?2 AND rev=?3",
            params![vault.to_string(), id, rev],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (Some(blob), Some(digest), _) = row.ok_or(Error::NotFound)? else {
        return Err(Error::NotFound);
    };
    let key = BlobKey {
        vault,
        object: blob.parse().map_err(|_| Error::Integrity)?,
    };
    let info = crate::sync::blob_info(c, key)?;
    if digest != info.digest {
        return Err(Error::Integrity);
    }
    let mut history = Vec::new();
    let mut cursor = Some(rev.clone());
    if options.revs || options.revs_info {
        while let Some(rev) = cursor {
            if history.len() >= MAX_ANCESTRY {
                break;
            }
            let (parent,available):(Option<String>,bool)=c.query_row("SELECT parent,blob IS NOT NULL FROM couch_revisions WHERE vault=?1 AND id=?2 AND rev=?3",params![vault.to_string(),id,rev],|r|Ok((r.get(0)?,r.get(1)?)))?;
            history.push((rev, available));
            cursor = parent;
        }
    }
    let conflicts = current
        .iter()
        .filter(|(r, deleted)| !deleted && r != &rev)
        .map(|(r, _)| r.clone())
        .collect();
    let deleted_conflicts = current
        .iter()
        .filter(|(r, deleted)| *deleted && r != &rev)
        .map(|(r, _)| r.clone())
        .collect();
    Ok(ReadPlan {
        info,
        rev,
        history,
        conflicts,
        deleted_conflicts,
    })
}
impl Couch {
    async fn materialize(
        &self,
        who: &Identity,
        plan: ReadPlan,
        options: &ReadOptions,
    ) -> Result<Value> {
        if plan.info.size > self.options.max_document_bytes as u64 {
            return Err(Error::Limit);
        }
        let (info, reader) = self.engine.read_blob(who, plan.info.key).await?;
        let mut bytes = Vec::with_capacity(info.size as usize);
        reader.take(info.size + 1).read_to_end(&mut bytes).await?;
        let mut doc: Value = super::cpu()?
            .run(move || {
                if bytes.len() as u64 != info.size
                    || <[u8; 32]>::from(Sha256::digest(&bytes)) != info.digest
                {
                    return Err(Error::Integrity);
                }
                serde_json::from_slice(&bytes).map_err(|_| Error::Integrity)
            })
            .await?;
        let object = doc.as_object_mut().ok_or(Error::Integrity)?;
        object.insert("_rev".into(), json!(plan.rev));
        if options.revs {
            object.insert("_revisions".into(),json!({"start":parse_revision(&plan.rev)?.0,"ids":plan.history.iter().map(|(r,_)|parse_revision(r).map(|(_,suffix)|suffix.to_owned())).collect::<Result<Vec<_>>>()?}));
        }
        if options.revs_info {
            object.insert("_revs_info".into(),Value::Array(plan.history.iter().map(|(rev,available)|json!({"rev":rev,"status":if *available{"available"}else{"missing"}})).collect()));
        }
        if options.conflicts && !plan.conflicts.is_empty() {
            object.insert("_conflicts".into(), json!(plan.conflicts));
        }
        if options.deleted_conflicts && !plan.deleted_conflicts.is_empty() {
            object.insert("_deleted_conflicts".into(), json!(plan.deleted_conflicts));
        }
        Ok(doc)
    }
    pub async fn get(
        &self,
        who: &Identity,
        vault: Uuid,
        id: &str,
        options: ReadOptions,
    ) -> Result<Value> {
        validate_id(id)?;
        if id.starts_with("_local/") {
            let who = who.clone();
            let id = id.to_owned();
            return self
                .db
                .run(move |c| {
                    authorize(c, &who, vault, false)?;
                    let row: Option<(i64, Vec<u8>)> = c
                        .query_row(
                            "SELECT revision,body FROM couch_local WHERE vault=?1 AND id=?2",
                            params![vault.to_string(), id],
                            |r| Ok((r.get(0)?, r.get(1)?)),
                        )
                        .optional()?;
                    let (rev, bytes) = row.ok_or(Error::NotFound)?;
                    let mut doc: Value = serde_json::from_slice(&bytes)?;
                    doc["_rev"] = json!(format!("0-{rev}"));
                    Ok(doc)
                })
                .await;
        }
        let identity = who.clone();
        let id = id.to_owned();
        let opts = options.clone();
        let plan = self
            .db
            .run(move |c| {
                let tx = c.transaction()?;
                authorize(&tx, &identity, vault, false)?;
                plan(&tx, vault, &id, &opts)
            })
            .await?;
        self.materialize(who, plan, &options).await
    }
    pub async fn open_revs(
        &self,
        who: &Identity,
        vault: Uuid,
        id: &str,
        revs: Option<Vec<String>>,
        options: ReadOptions,
    ) -> Result<Value> {
        validate_id(id)?;
        let identity = who.clone();
        let id = id.to_owned();
        let opts = options.clone();
        let limit = self.options.max_response_bytes;
        let plans = self
            .db
            .run(move |c| {
                let tx = c.transaction()?;
                authorize(&tx, &identity, vault, false)?;
                let mut revisions = match revs {
                    Some(revisions) => revisions,
                    None => leaves(&tx, vault, &id)?
                        .into_iter()
                        .map(|(r, _)| r)
                        .collect(),
                };
                if revisions.len() > 256 {
                    return Err(Error::Limit);
                }
                if opts.latest {
                    let mut expanded = Vec::new();
                    let mut seen = std::collections::HashSet::new();
                    for rev in revisions {
                        let found = descendants(&tx, vault, &id, &rev)?;
                        if found.is_empty() {
                            if seen.insert(rev.clone()) {
                                expanded.push(rev);
                            }
                        } else {
                            for leaf in found {
                                if seen.insert(leaf.clone()) {
                                    expanded.push(leaf);
                                }
                            }
                        }
                    }
                    if expanded.len() > 256 {
                        return Err(Error::Limit);
                    }
                    revisions = expanded;
                }
                let mut bytes = 0;
                let mut plans = Vec::new();
                for rev in revisions {
                    let options = ReadOptions {
                        rev: Some(rev.clone()),
                        latest: false,
                        ..opts.clone()
                    };
                    match plan(&tx, vault, &id, &options) {
                        Ok(plan) => {
                            bytes += plan.info.size as usize + 4096;
                            if bytes > limit {
                                return Err(Error::Limit);
                            }
                            plans.push((rev, Some(plan)));
                        }
                        Err(Error::NotFound) => plans.push((rev, None)),
                        Err(e) => return Err(e),
                    }
                }
                Ok(plans)
            })
            .await?;
        let mut result = Vec::new();
        let mut heap = 0;
        for (rev, plan) in plans {
            let value = match plan {
                Some(plan) => json!({"ok":self.materialize(who,plan,&options).await?}),
                None => json!({"missing":rev}),
            };
            let (_, cost, value) = super::measured(value).await?;
            heap += cost;
            if heap > super::json::HEAP_PAGE {
                return Err(Error::TooLarge);
            }
            result.push(value);
        }
        Ok(json!(result))
    }
    pub async fn revs_diff(&self, who: &Identity, vault: Uuid, request: Value) -> Result<Value> {
        let object = request.as_object().ok_or(Error::Invalid)?;
        if object.len() > self.options.max_batch_docs {
            return Err(Error::Limit);
        }
        let mut wanted = Vec::new();
        let mut count = 0;
        for (id, revisions) in object {
            validate_id(id)?;
            let revisions = revisions.as_array().ok_or(Error::Invalid)?;
            let mut values = Vec::new();
            for rev in revisions {
                let rev = rev.as_str().ok_or(Error::Invalid)?;
                parse_revision(rev)?;
                values.push(rev.to_owned());
            }
            count += values.len();
            if count > self.options.max_batch_docs * 4 {
                return Err(Error::Limit);
            }
            wanted.push((id.clone(), values));
        }
        let who = who.clone();
        self.db
            .run(move |c| {
                let tx = c.transaction()?;
                authorize(&tx, &who, vault, false)?;
                let mut result = serde_json::Map::new();
                for (id, revisions) in wanted {
                    let mut missing = Vec::new();
                    for rev in revisions {
                        let found: bool = tx.query_row(
                            "SELECT EXISTS(SELECT 1 FROM couch_revisions
                         WHERE vault=?1 AND id=?2 AND rev=?3 AND blob IS NOT NULL)",
                            params![vault.to_string(), id, rev],
                            |r| r.get(0),
                        )?;
                        if !found {
                            missing.push(rev);
                        }
                    }
                    if !missing.is_empty() {
                        result.insert(id, json!({"missing":missing}));
                    }
                }
                Ok(Value::Object(result))
            })
            .await
    }
    pub async fn bulk_get(
        &self,
        who: &Identity,
        vault: Uuid,
        request: Value,
        options: ReadOptions,
    ) -> Result<Value> {
        let docs = request
            .get("docs")
            .and_then(Value::as_array)
            .ok_or(Error::Invalid)?;
        if docs.len() > self.options.max_batch_docs {
            return Err(Error::Limit);
        }
        let mut results = Vec::new();
        let mut size = 0;
        let mut heap = 0;
        for item in docs {
            let id = item
                .get("id")
                .and_then(Value::as_str)
                .ok_or(Error::Invalid)?;
            let rev = item
                .get("rev")
                .map(|r| r.as_str().map(str::to_owned).ok_or(Error::Invalid))
                .transpose()?;
            let opts = ReadOptions {
                rev: rev.clone(),
                ..options.clone()
            };
            let value = if let Some(revision) = rev.as_ref().filter(|_| options.latest) {
                let rows = self
                    .open_revs(who, vault, id, Some(vec![revision.clone()]), opts)
                    .await?;
                let mut values = Vec::new();
                let Value::Array(rows) = rows else {
                    return Err(Error::Integrity);
                };
                for row in rows {
                    if row.get("ok").is_some() {
                        values.push(row);
                    } else {
                        values.push(json!({"error":{"id":id,"rev":row["missing"],"error":"not_found","reason":"missing"}}));
                    }
                }
                json!({"id":id,"docs":values})
            } else {
                match self.get(who, vault, id, opts).await {
                    Ok(doc) => json!({"id":id,"docs":[{"ok":doc}]}),
                    Err(Error::NotFound) => {
                        json!({"id":id,"docs":[{"error":{"id":id,"rev":rev,"error":"not_found","reason":"missing"}}]})
                    }
                    Err(e) => return Err(e),
                }
            };
            let (length, cost, value) = super::measured(value).await?;
            size += length;
            heap += cost;
            if size > self.options.max_response_bytes || heap > super::json::HEAP_PAGE {
                return Err(Error::TooLarge);
            }
            results.push(value);
        }
        Ok(json!({"results":results}))
    }
}

#[derive(Clone, Default)]
pub struct ListOptions {
    pub keys: Option<Vec<String>>,
    pub start: Option<String>,
    pub end: Option<String>,
    pub inclusive_end: bool,
    pub descending: bool,
    pub include_docs: bool,
    pub conflicts: bool,
    pub limit: usize,
    pub skip: usize,
    pub update_seq: bool,
}
#[derive(Clone)]
pub struct ChangeOptions {
    pub since: i64,
    pub limit: usize,
    pub include_docs: bool,
    pub read: ReadOptions,
    pub filter: Filter,
}

#[derive(Clone, Default)]
pub enum Filter {
    #[default]
    All,
    Type {
        value: String,
        equal: bool,
    },
    Ids(Vec<String>),
}
impl Filter {
    pub fn parse(selector: &Value) -> Result<Self> {
        let obj = selector.as_object().ok_or(Error::Invalid)?;
        if obj.len() != 1 {
            return Err(Error::Unsupported);
        }
        let value = obj.get("type").ok_or(Error::Unsupported)?;
        if let Some(value) = value.as_str() {
            return Ok(Self::Type {
                value: value.to_owned(),
                equal: true,
            });
        }
        let op = value.as_object().ok_or(Error::Unsupported)?;
        if op.len() != 1 {
            return Err(Error::Unsupported);
        }
        let (key, value) = op.iter().next().ok_or(Error::Invalid)?;
        let value = value
            .as_str()
            .filter(|s| s.len() <= 64)
            .ok_or(Error::Unsupported)?;
        match key.as_str() {
            "$eq" => Ok(Self::Type {
                value: value.into(),
                equal: true,
            }),
            "$ne" => Ok(Self::Type {
                value: value.into(),
                equal: false,
            }),
            _ => Err(Error::Unsupported),
        }
    }
}
impl Couch {
    pub async fn all_docs(
        &self,
        who: &Identity,
        vault: Uuid,
        options: ListOptions,
    ) -> Result<Value> {
        let identity = who.clone();
        let opts = options.clone();
        let max = self.options.max_batch_docs;
        if opts.limit > max
            || opts.skip > 100000
            || opts.keys.as_ref().is_some_and(|k| k.len() > max)
        {
            return Err(Error::Limit);
        }
        if let Some(keys) = &opts.keys {
            for key in keys {
                validate_id(key)?;
            }
        }
        let (total, seq, rows) = self
            .db
            .run(move |c| {
                let tx = c.transaction()?;
                authorize(&tx, &identity, vault, false)?;
                let seq: i64 = tx.query_row(
                    "SELECT seq FROM couch_databases WHERE vault=?1",
                    [vault.to_string()],
                    |r| r.get(0),
                )?;
                let total: i64 = tx.query_row(
                    "SELECT count(*) FROM couch_heads h JOIN couch_revisions r
                 ON r.vault=h.vault AND r.id=h.id AND r.rev=h.winner
                 WHERE h.vault=?1 AND r.deleted=0",
                    [vault.to_string()],
                    |r| r.get(0),
                )?;
                let mut rows = Vec::new();
                if let Some(keys) = opts.keys {
                    for key in keys {
                        let row: Option<(String, bool)> = tx.query_row(
                        "SELECT h.winner,r.deleted FROM couch_heads h JOIN couch_revisions r
                         ON r.vault=h.vault AND r.id=h.id AND r.rev=h.winner
                         WHERE h.vault=?1 AND h.id=?2",
                        params![vault.to_string(), key],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    ).optional()?;
                        rows.push((key, row));
                    }
                } else {
                    let order = if opts.descending { "DESC" } else { "ASC" };
                    let compare_start = if opts.descending { "<=" } else { ">=" };
                    let compare_end = match (opts.descending, opts.inclusive_end) {
                        (false, true) => "<=",
                        (false, false) => "<",
                        (true, true) => ">=",
                        (true, false) => ">",
                    };
                    // All SQL fragments are static enum choices; user keys remain bound parameters.
                    let sql = format!(
                        "SELECT h.id,h.winner,r.deleted FROM couch_heads h JOIN couch_revisions r
                     ON r.vault=h.vault AND r.id=h.id AND r.rev=h.winner
                     WHERE h.vault=?1 AND r.deleted=0
                     AND (?2 IS NULL OR h.id {compare_start} ?2)
                     AND (?3 IS NULL OR h.id {compare_end} ?3)
                     ORDER BY h.id {order} LIMIT ?4 OFFSET ?5"
                    );
                    let mut stmt = tx.prepare(&sql)?;
                    rows = stmt
                        .query_map(
                            params![
                                vault.to_string(),
                                opts.start,
                                opts.end,
                                opts.limit as i64,
                                opts.skip as i64
                            ],
                            |r| Ok((r.get::<_, String>(0)?, Some((r.get(1)?, r.get(2)?)))),
                        )?
                        .collect::<std::result::Result<_, _>>()?;
                }
                Ok((total, seq, rows))
            })
            .await?;
        let mut result = Vec::new();
        let mut size = 0;
        let mut heap = 0;
        for (key, row) in rows {
            let mut value = match row {
                None => json!({"key":key,"error":"not_found"}),
                Some((rev, deleted)) => {
                    let mut value = json!({"id":key,"key":key,"value":{"rev":rev}});
                    if deleted {
                        value["value"]["deleted"] = json!(true);
                    }
                    if options.include_docs {
                        if deleted {
                            value["doc"] = Value::Null;
                        } else {
                            value["doc"] = self
                                .get(
                                    who,
                                    vault,
                                    &key,
                                    ReadOptions {
                                        rev: Some(rev),
                                        conflicts: options.conflicts,
                                        ..Default::default()
                                    },
                                )
                                .await?;
                        }
                    }
                    value
                }
            };
            if options.include_docs && value.get("doc").is_none() && value.get("error").is_none() {
                value["doc"] = Value::Null;
            }
            let (length, cost, value) = super::measured(value).await?;
            size += length;
            heap += cost;
            if size > self.options.max_response_bytes || heap > super::json::HEAP_PAGE {
                return Err(Error::TooLarge);
            }
            result.push(value);
        }
        let mut response = json!({"total_rows":total,"offset":options.skip,"rows":result});
        if options.update_seq {
            response["update_seq"] = json!(seq);
        }
        Ok(response)
    }
    pub async fn changes(
        &self,
        who: &Identity,
        vault: Uuid,
        request: ChangeOptions,
    ) -> Result<Value> {
        let ChangeOptions {
            since,
            limit,
            include_docs,
            read: options,
            filter,
        } = request;
        if since < 0 || limit > self.options.max_batch_docs {
            return Err(Error::Invalid);
        }
        let identity = who.clone();
        let filter = filter.clone();
        let opts = options.clone();
        let (seq, rows, pending) = self.db.run(move |c| {
            let tx = c.transaction()?;
            authorize(&tx, &identity, vault, false)?;
            let seq: i64 = tx.query_row(
                "SELECT seq FROM couch_databases WHERE vault=?1",
                [vault.to_string()],
                |r| r.get(0),
            )?;
            if since > seq {
                return Err(Error::Invalid);
            }
            let (kind, equal, ids) = match filter {
                Filter::All => (None, false, None),
                Filter::Type { value, equal } => (Some(value), equal, None),
                Filter::Ids(ids) => (None, false, Some(serde_json::to_string(&ids)?)),
            };
            let predicate = "h.vault=?1 AND h.seq>?2
                AND (?3 IS NULL OR CASE WHEN ?4 THEN r.kind=?3 ELSE r.kind IS NULL OR r.kind<>?3 END)
                AND (?5 IS NULL OR h.id IN (SELECT value FROM json_each(?5)))";
            let mut stmt = tx.prepare(&format!(
                "SELECT h.id,h.winner,h.seq,r.deleted FROM couch_heads h JOIN couch_revisions r
                 ON r.vault=h.vault AND r.id=h.id AND r.rev=h.winner
                 WHERE {predicate} ORDER BY h.seq LIMIT ?6"
            ))?;
            let rows = stmt.query_map(
                params![vault.to_string(), since, kind, equal, ids, limit as i64],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?, r.get::<_, bool>(3)?)),
            )?.collect::<std::result::Result<Vec<_>, _>>()?;
            let count: i64 = tx.query_row(
                &format!("SELECT count(*) FROM couch_heads h JOIN couch_revisions r
                    ON r.vault=h.vault AND r.id=h.id AND r.rev=h.winner WHERE {predicate}"),
                params![vault.to_string(), since, kind, equal, ids],
                |r| r.get(0),
            )?;
            let mut selected = Vec::new();
            for (id, winner, sequence, deleted) in rows {
                let revisions = leaves(&tx, vault, &id)?;
                let plan = if include_docs {
                    Some(plan(&tx, vault, &id, &ReadOptions {
                        rev: Some(winner),
                        ..opts.clone()
                    })?)
                } else {
                    None
                };
                selected.push((id, sequence, deleted, revisions, plan));
            }
            let pending = count - selected.len() as i64;
            Ok((seq, selected, pending))
        }).await?;
        let mut results = Vec::new();
        let mut size = 0;
        let mut heap = 0;
        let mut last = since;
        let mut pending = pending;
        let selected = rows.len();
        for (index, (id, sequence, deleted, revisions, plan)) in rows.into_iter().enumerate() {
            let mut row = json!({"id":id,"seq":sequence,"changes":revisions.into_iter().take(if options.all_leaves{usize::MAX}else{1}).map(|(rev,_)|json!({"rev":rev})).collect::<Vec<_>>()});
            if deleted {
                row["deleted"] = json!(true);
            }
            if let Some(plan) = plan {
                row["doc"] = self.materialize(who, plan, &options).await?;
            }
            let (length, cost, row) = super::measured(row).await?;
            if size + length > self.options.max_response_bytes.saturating_sub(4096)
                || heap + cost > super::json::HEAP_PAGE
            {
                if results.is_empty() {
                    return Err(Error::TooLarge);
                }
                pending += (selected - index) as i64;
                break;
            }
            size += length;
            heap += cost;
            last = sequence;
            results.push(row);
        }
        if pending == 0 {
            last = seq;
        }
        Ok(json!({"results":results,"last_seq":last,"pending":pending}))
    }
}
