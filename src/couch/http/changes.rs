//! Bounded changes feeds; waiting releases execution, response bodies retain active permits.
use super::{ApiError, ApiResult, App, Query, response, wire_sequences};
use crate::{
    Error,
    auth::Identity,
    couch::{
        cpu, parse_sequence,
        reads::{ChangeOptions, Filter},
        revisions::validate_id,
    },
};
use axum::{
    body::Body,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

fn with_active(mut response: Response, permit: tokio::sync::OwnedSemaphorePermit) -> Response {
    response.extensions_mut().insert(Arc::new(permit));
    response
}
pub(super) async fn handle(
    app: &App,
    who: &Identity,
    name: &str,
    vault: Uuid,
    query: &Query,
    body: Value,
) -> ApiResult<Response> {
    let filter = match query.get("filter") {
        None => {
            if let Some(selector) = body.get("selector") {
                Filter::parse(selector)?
            } else {
                Filter::All
            }
        }
        Some("_selector") => Filter::parse(
            body.get("selector")
                .or(query.json("selector")?.as_ref())
                .ok_or(Error::Invalid)?,
        )?,
        Some("_doc_ids") => {
            let value = body
                .get("doc_ids")
                .cloned()
                .or(query.json("doc_ids")?)
                .ok_or(Error::Invalid)?;
            let ids: Vec<String> = serde_json::from_value(value).map_err(|_| Error::Invalid)?;
            if ids.len() > app.couch.options.max_batch_docs {
                return Err(ApiError::large());
            }
            for id in &ids {
                validate_id(id)?;
            }
            Filter::Ids(ids)
        }
        _ => return Err(Error::Unsupported.into()),
    };
    let info = app.couch.info(who, name, vault).await?;
    let since = match query.get("since") {
        Some("now") => info["update_seq"].as_i64().ok_or(Error::Integrity)?,
        Some(s) => parse_sequence(vault, s)?,
        None => 0,
    };
    let limit = query
        .number("limit", app.couch.options.max_batch_docs)?
        .min(app.couch.options.max_batch_docs);
    let include = query.boolean("include_docs")?;
    let options = query.read_options()?;
    let feed = query.get("feed").unwrap_or("normal");
    if !matches!(feed, "normal" | "longpoll" | "continuous") {
        return Err(Error::Unsupported.into());
    }
    let timeout = query
        .number(
            "timeout",
            (app.couch.options.longpoll_seconds * 1000) as usize,
        )?
        .min((app.couch.options.longpoll_seconds * 1000) as usize);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout as u64);
    let mut stop = app.couch.stop.clone();
    let (page, active) = loop {
        let active = app
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| ApiError::busy())?;
        let notified = app.couch.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let page = app
            .couch
            .changes(
                who,
                vault,
                ChangeOptions {
                    since,
                    limit,
                    include_docs: include,
                    read: options.clone(),
                    filter: filter.clone(),
                },
            )
            .await?;
        if feed == "normal"
            || page["results"].as_array().is_some_and(|r| !r.is_empty())
            || limit == 0
            || *stop.borrow()
            || tokio::time::Instant::now() >= deadline
        {
            break (page, active);
        }
        drop(active);
        tokio::select! {_=notified=>(),_=tokio::time::sleep_until(deadline)=>(),_=stop.changed()=>()}
    };
    let page = wire_sequences(page, vault);
    if feed != "continuous" {
        return Ok(with_active(
            response(StatusCode::OK, page, app.couch.options.max_response_bytes).await?,
            active,
        ));
    }
    let rows = page
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(Error::Integrity)?;
    let last = page["last_seq"].clone();
    let pending = page["pending"].clone();
    let stream = async_stream::try_stream! {
        for row in rows {
            let mut bytes = cpu().map_err(std::io::Error::other)?
                .run(move || Ok(serde_json::to_vec(&row)?)).await.map_err(std::io::Error::other)?;
            bytes.push(b'\n');
            yield bytes;
        }
        let mut bytes = serde_json::to_vec(&json!({"last_seq":last,"pending":pending}))
            .map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        yield bytes;
    };
    let body = Body::from_stream(stream.map(|r: std::result::Result<Vec<u8>, std::io::Error>| r));
    Ok(with_active(
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        active,
    ))
}
