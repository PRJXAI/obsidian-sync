//! Document and local-checkpoint wire operations; revision semantics stay in Couch.
use super::{
    ApiError, ApiResult, App,
    codec::{Query, body_json, response},
};
use crate::{
    Error,
    auth::Identity,
    couch::{measured, revisions::validate_id},
};
use axum::{
    extract::Request,
    http::{Method, StatusCode, header},
    response::Response,
};
use serde_json::{Value, json};
use uuid::Uuid;

pub(super) async fn handle(
    app: &App,
    who: &Identity,
    vault: Uuid,
    id: String,
    method: Method,
    query: &Query,
    request: Request,
) -> ApiResult<Response> {
    if id.starts_with('_') && !id.starts_with("_local/") && !id.starts_with("_design/") {
        return Err(Error::Unsupported.into());
    }
    validate_id(&id)?;
    let max = app.couch.options.max_response_bytes;
    match method {
        Method::GET | Method::HEAD => {
            let opts = query.read_options()?;
            let value = if let Some(open) = query.get("open_revs") {
                let revs = if open == "all" {
                    None
                } else {
                    Some(serde_json::from_str::<Vec<String>>(open).map_err(|_| Error::Invalid)?)
                };
                app.couch.open_revs(who, vault, &id, revs, opts).await?
            } else {
                app.couch.get(who, vault, &id, opts).await?
            };
            let mut result = response(StatusCode::OK, value.clone(), max).await?;
            if let Some(rev) = value.get("_rev").and_then(Value::as_str) {
                result.headers_mut().insert(
                    header::ETAG,
                    format!("\"{rev}\"").parse().map_err(|_| Error::Integrity)?,
                );
            }
            Ok(result)
        }
        Method::PUT => {
            let if_match = request
                .headers()
                .get(header::IF_MATCH)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim_matches('"').to_owned());
            let mut value = body_json(request, app.couch.options.max_request_bytes).await?;
            if !value.is_object() {
                return Err(Error::Invalid.into());
            }
            if value.get("_id").is_some_and(|v| v.as_str() != Some(&id)) {
                return Err(Error::Invalid.into());
            }
            value["_id"] = json!(id);
            let rev = query.get("rev").map(str::to_owned).or(if_match);
            if let Some(rev) = rev {
                if value.get("_rev").is_some_and(|r| r.as_str() != Some(&rev)) {
                    return Err(Error::Conflict.into());
                }
                value["_rev"] = json!(rev);
            }
            let new_edits = if query.get("new_edits").is_some() {
                query.boolean("new_edits")?
            } else {
                true
            };
            put(app, who, vault, value, new_edits).await
        }
        Method::DELETE => {
            let rev = query.get("rev").ok_or(Error::Conflict)?;
            put(
                app,
                who,
                vault,
                json!({"_id":id,"_rev":rev,"_deleted":true}),
                true,
            )
            .await
        }
        _ => Err(Error::Unsupported.into()),
    }
}

pub(super) async fn put(
    app: &App,
    who: &Identity,
    vault: Uuid,
    value: Value,
    new_edits: bool,
) -> ApiResult<Response> {
    let (length, _, value) = measured(value).await?;
    if length > app.couch.options.max_document_bytes {
        return Err(ApiError::large());
    }
    let result = app.couch.put(who, vault, value, new_edits).await?;
    let rev = result.get("rev").and_then(Value::as_str).map(str::to_owned);
    let mut response = response(
        StatusCode::CREATED,
        result,
        app.couch.options.max_response_bytes,
    )
    .await?;
    if let Some(rev) = rev {
        response.headers_mut().insert(
            header::ETAG,
            format!("\"{rev}\"").parse().map_err(|_| Error::Integrity)?,
        );
    }
    Ok(response)
}
