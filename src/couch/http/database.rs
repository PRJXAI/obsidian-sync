//! Operations on an already resolved, active database alias.
use super::{
    ApiResult, App,
    codec::{body_json, response, wire_sequences},
    document::put,
};
use crate::{Error, auth::Identity};
use axum::{
    Json,
    extract::Request,
    http::Method,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use uuid::Uuid;

pub(super) async fn handle(
    app: &App,
    who: &Identity,
    name: &str,
    vault: Uuid,
    method: Method,
    request: Request,
) -> ApiResult<Response> {
    let max = app.couch.options.max_response_bytes;
    match method {
        Method::GET | Method::HEAD => {
            response(
                StatusCode::OK,
                wire_sequences(app.couch.info(who, name, vault).await?, vault),
                max,
            )
            .await
        }
        Method::PUT => Ok((
            StatusCode::PRECONDITION_FAILED,
            Json(json!({"error":"file_exists","reason":"Database is already provisioned"})),
        )
            .into_response()),
        Method::DELETE => {
            app.couch.reset(who, name, vault).await?;
            response(StatusCode::OK, json!({"ok":true}), max).await
        }
        Method::POST => {
            let mut value = body_json(request, app.couch.options.max_request_bytes).await?;
            if value.get("_id").is_none() {
                value["_id"] = json!(Uuid::new_v4().simple().to_string());
            }
            put(app, who, vault, value, true).await
        }
        _ => Err(Error::Unsupported.into()),
    }
}
