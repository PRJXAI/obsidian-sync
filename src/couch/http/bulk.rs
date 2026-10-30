//! Bulk replication and bounded document listing endpoints.
use super::{
    ApiError, ApiResult, App,
    codec::{Query, body_json, response, wire_sequences},
};
use crate::{
    Error,
    auth::Identity,
    couch::{measured, reads::ListOptions},
};
use axum::{
    extract::Request,
    http::{Method, StatusCode},
    response::Response,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn revs_diff(
    app: &App,
    who: &Identity,
    vault: Uuid,
    request: Request,
) -> ApiResult<Response> {
    response(
        StatusCode::OK,
        app.couch
            .revs_diff(
                who,
                vault,
                body_json(request, app.couch.options.max_request_bytes).await?,
            )
            .await?,
        app.couch.options.max_response_bytes,
    )
    .await
}

pub(super) async fn get(
    app: &App,
    who: &Identity,
    vault: Uuid,
    query: &Query,
    request: Request,
) -> ApiResult<Response> {
    response(
        StatusCode::OK,
        app.couch
            .bulk_get(
                who,
                vault,
                body_json(request, app.couch.options.max_request_bytes).await?,
                query.read_options()?,
            )
            .await?,
        app.couch.options.max_response_bytes,
    )
    .await
}

pub(super) async fn put(
    app: &App,
    who: &Identity,
    vault: Uuid,
    request: Request,
) -> ApiResult<Response> {
    let body = body_json(request, app.couch.options.max_request_bytes).await?;
    let docs = body
        .get("docs")
        .and_then(Value::as_array)
        .ok_or(Error::Invalid)?;
    if docs.len() > app.couch.options.max_batch_docs {
        return Err(ApiError::large());
    }
    let new_edits = body
        .get("new_edits")
        .map(|v| v.as_bool().ok_or(Error::Invalid))
        .transpose()?
        .unwrap_or(true);
    let mut results = Vec::new();
    for doc in docs {
        let mut doc = doc.clone();
        if new_edits && doc.is_object() && doc.get("_id").is_none() {
            doc["_id"] = json!(Uuid::new_v4().simple().to_string());
        }
        let id = doc.get("_id").cloned().unwrap_or(Value::Null);
        let rev = doc.get("_rev").cloned();
        let (length, _, doc) = measured(doc).await?;
        let result = if length > app.couch.options.max_document_bytes {
            Err(ApiError::large())
        } else {
            app.couch
                .put(who, vault, doc, new_edits)
                .await
                .map_err(ApiError::from)
        };
        match result {
            Ok(row) if new_edits => results.push(row),
            Ok(_) => (),
            Err(error) => {
                let mut row = error.object();
                row["id"] = id;
                if let Some(rev) = rev {
                    row["rev"] = rev;
                }
                results.push(row);
            }
        }
    }
    response(
        StatusCode::CREATED,
        json!(results),
        app.couch.options.max_response_bytes,
    )
    .await
}

pub(super) async fn all_docs(
    app: &App,
    who: &Identity,
    vault: Uuid,
    method: Method,
    query: &Query,
    request: Request,
) -> ApiResult<Response> {
    let body = if method == Method::POST {
        Some(body_json(request, app.couch.options.max_request_bytes).await?)
    } else {
        None
    };
    let keys = body
        .as_ref()
        .and_then(|b| b.get("keys"))
        .cloned()
        .or(query.json("keys")?)
        .map(|v| serde_json::from_value::<Vec<String>>(v).map_err(|_| Error::Invalid))
        .transpose()?;
    let start = query
        .json("startkey")?
        .or(query.json("start_key")?)
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Invalid))
        .transpose()?;
    let end = query
        .json("endkey")?
        .or(query.json("end_key")?)
        .map(|v| v.as_str().map(str::to_owned).ok_or(Error::Invalid))
        .transpose()?;
    let options = ListOptions {
        keys,
        start,
        end,
        inclusive_end: query.get("inclusive_end") != Some("false"),
        descending: query.boolean("descending")?,
        include_docs: query.boolean("include_docs")?,
        conflicts: query.boolean("conflicts")?,
        limit: query
            .number("limit", app.couch.options.max_batch_docs)?
            .min(app.couch.options.max_batch_docs),
        skip: query.number("skip", 0)?,
        update_seq: query.boolean("update_seq")?,
    };
    response(
        StatusCode::OK,
        wire_sequences(app.couch.all_docs(who, vault, options).await?, vault),
        app.couch.options.max_response_bytes,
    )
    .await
}
