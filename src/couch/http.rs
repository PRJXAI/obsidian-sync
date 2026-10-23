//! Bounded HTTP adapter for the verified LiveSync/PouchDB replication contract.
use super::{
    Couch,
    reads::{ChangeOptions, Filter, ListOptions, ReadOptions},
    revisions::validate_id,
};
use crate::{Error, auth::Identity};
use axum::{
    Json, Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tower_http::cors::CorsLayer;
use uuid::Uuid;

#[derive(Clone)]
struct App {
    couch: Couch,
    slots: Arc<Semaphore>,
    admission: Arc<Semaphore>,
    poll_slots: Arc<Semaphore>,
    rates: Arc<Mutex<Rates>>,
}
struct Bucket {
    tokens: f64,
    last: Instant,
}
struct Rates {
    global: Bucket,
    devices: HashMap<String, Bucket>,
}
impl Bucket {
    fn take(&mut self, burst: u32, per_minute: u32) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens
            + now.duration_since(self.last).as_secs_f64() * per_minute as f64 / 60.0)
            .min(burst as f64);
        self.last = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    reason: &'static str,
}
impl ApiError {
    fn auth() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            reason: "Authentication required",
        }
    }
    fn busy() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_requests",
            reason: "Retry later",
        }
    }
    fn large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "request_entity_too_large",
            reason: "Configured transfer limit exceeded",
        }
    }
    fn object(&self) -> Value {
        json!({"error":self.code,"reason":self.reason,"status":self.status.as_u16()})
    }
}
impl From<Error> for ApiError {
    fn from(error: Error) -> Self {
        let (status, code, reason) = match error {
            Error::Invalid => (StatusCode::BAD_REQUEST, "bad_request", "Invalid request"),
            Error::Unauthorized => (StatusCode::FORBIDDEN, "forbidden", "Access denied"),
            Error::Conflict => (StatusCode::CONFLICT, "conflict", "Document update conflict"),
            Error::NotFound => (StatusCode::NOT_FOUND, "not_found", "missing"),
            Error::Unsupported => (
                StatusCode::NOT_IMPLEMENTED,
                "not_implemented",
                "Operation is outside the supported LiveSync protocol",
            ),
            Error::TooLarge => return Self::large(),
            Error::Limit => (
                StatusCode::INSUFFICIENT_STORAGE,
                "insufficient_storage",
                "Configured resource quota exceeded",
            ),
            Error::Timeout => (
                StatusCode::GATEWAY_TIMEOUT,
                "timeout",
                "Operation timed out",
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_server_error",
                "Operation failed",
            ),
        };
        Self {
            status,
            code,
            reason,
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut response = (self.status, Json(self.object())).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"obsidian-sync\""),
            );
        }
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        response
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;

pub fn router(couch: Couch) -> crate::Result<Router> {
    let origins = couch
        .options
        .allowed_origins
        .iter()
        .map(|s| s.parse::<HeaderValue>().map_err(|_| Error::Invalid))
        .collect::<crate::Result<Vec<_>>>()?;
    let app = App {
        slots: Arc::new(Semaphore::new(couch.options.max_requests)),
        admission: Arc::new(Semaphore::new(couch.options.max_requests * 2)),
        poll_slots: Arc::new(Semaphore::new(32)),
        rates: Arc::new(Mutex::new(Rates {
            global: Bucket {
                tokens: couch.options.burst as f64,
                last: Instant::now(),
            },
            devices: HashMap::new(),
        })),
        couch,
    };
    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            header::IF_MATCH,
            header::IF_NONE_MATCH,
            header::HeaderName::from_static("x-couch-full-commit"),
            header::HeaderName::from_static("x-requested-with"),
        ])
        .expose_headers([
            header::ETAG,
            header::HeaderName::from_static("x-couch-update-newrev"),
        ]);
    Ok(Router::new()
        .route("/health/live", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/health/ready",
            get(|State(app): State<App>| async move {
                if *app.couch.stop.borrow() {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::NO_CONTENT
                }
            }),
        )
        .fallback(any(dispatch))
        .with_state(app.clone())
        .layer(middleware::from_fn_with_state(app, guard))
        .layer(cors))
}
async fn guard(State(app): State<App>, request: Request, next: Next) -> Response {
    if matches!(request.uri().path(), "/health/live" | "/health/ready") {
        return next.run(request).await;
    }
    if *app.couch.stop.borrow() {
        return ApiError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "service_unavailable",
            reason: "Shutting down",
        }
        .into_response();
    }
    if request.headers().get(header::ORIGIN).is_some_and(|v| {
        v.to_str().ok().is_none_or(|origin| {
            !app.couch
                .options
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
        })
    }) {
        return ApiError::from(Error::Unauthorized).into_response();
    }
    if request.uri().to_string().len() > 8192 {
        return ApiError::large().into_response();
    }
    // Waiting change feeds must not consume every execution slot and starve writes.
    let changes = request
        .uri()
        .path()
        .strip_prefix('/')
        .and_then(|p| p.split_once('/'))
        .and_then(|(_, tail)| decode(tail).ok())
        .as_deref()
        == Some("_changes");
    // Bound BOTH executing and queued normal work. A brief burst waits instead
    // of spuriously failing when a change page temporarily holds execution slots.
    let admission = if changes {
        app.poll_slots.clone()
    } else {
        app.admission.clone()
    };
    let permit = match admission.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => return ApiError::busy().into_response(),
    };
    let execution = if changes {
        None
    } else {
        match tokio::time::timeout(Duration::from_secs(1), app.slots.clone().acquire_owned()).await
        {
            Ok(Ok(p)) => Some(p),
            _ => return ApiError::busy().into_response(),
        }
    };
    let allowed = app
        .rates
        .lock()
        .map(|mut r| {
            r.global.take(
                app.couch.options.burst,
                app.couch.options.requests_per_minute * 4,
            )
        })
        .unwrap_or(false);
    if !allowed {
        return ApiError::busy().into_response();
    }
    if request.uri().to_string().len() > 8192 {
        return ApiError::large().into_response();
    }
    let result = tokio::time::timeout(Duration::from_secs(300), next.run(request)).await;
    let response = match result {
        Ok(r) => r,
        Err(_) => return ApiError::from(Error::Timeout).into_response(),
    };
    let (mut parts, body) = response.into_parts();
    let active = parts
        .extensions
        .remove::<Arc<tokio::sync::OwnedSemaphorePermit>>();
    let stream = async_stream::stream! {
        let _permit=permit;let _execution=execution;let _active=active;let mut input=body.into_data_stream();
        while let Some(chunk)=input.next().await{yield chunk;}
    };
    let mut response = Response::from_parts(parts, Body::from_stream(stream));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
async fn authenticate(app: &App, headers: &axum::http::HeaderMap) -> ApiResult<Identity> {
    let values = headers.get_all(header::AUTHORIZATION);
    let mut values = values.iter();
    let value = values.next().ok_or_else(ApiError::auth)?;
    if values.next().is_some() {
        return Err(ApiError::auth());
    }
    let value = value.to_str().map_err(|_| ApiError::auth())?;
    if value.len() > 1024 {
        return Err(ApiError::auth());
    }
    let (username, token) = if let Some(basic) = value.strip_prefix("Basic ") {
        let bytes = STANDARD.decode(basic).map_err(|_| ApiError::auth())?;
        let pair = String::from_utf8(bytes).map_err(|_| ApiError::auth())?;
        let (name, token) = pair.split_once(':').ok_or_else(ApiError::auth)?;
        (Some(name.to_owned()), token.to_owned())
    } else if let Some(token) = value.strip_prefix("Bearer ") {
        (None, token.to_owned())
    } else {
        return Err(ApiError::auth());
    };
    let who = app
        .couch
        .db
        .authenticate(&token)
        .await
        .map_err(|_| ApiError::auth())?;
    if username.as_deref().is_some_and(|u| u != who.id()) {
        return Err(ApiError::auth());
    }
    let mut rates = app.rates.lock().map_err(|_| ApiError::busy())?;
    if !rates.devices.contains_key(who.id()) {
        if rates.devices.len() >= 4096 {
            rates
                .devices
                .retain(|_, b| b.last.elapsed() < Duration::from_secs(300));
        }
        if rates.devices.len() >= 4096 {
            return Err(ApiError::busy());
        }
    }
    let bucket = rates.devices.entry(who.id().to_owned()).or_insert(Bucket {
        tokens: app.couch.options.burst as f64,
        last: Instant::now(),
    });
    if !bucket.take(
        app.couch.options.burst,
        app.couch.options.requests_per_minute,
    ) {
        return Err(ApiError::busy());
    }
    Ok(who)
}
fn decode(value: &str) -> ApiResult<String> {
    let bytes = value.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b'%'
            && (i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit())
        {
            return Err(Error::Invalid.into());
        }
    }
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| Error::Invalid.into())
}
#[derive(Default)]
struct Query(HashMap<String, String>);
impl Query {
    fn parse(raw: Option<&str>) -> ApiResult<Self> {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_str(raw.unwrap_or(""))
            .map_err(|_| ApiError::from(Error::Invalid))?;
        if pairs.len() > 32 {
            return Err(ApiError::large());
        }
        let mut map = HashMap::new();
        for (k, v) in pairs {
            if map.insert(k, v).is_some() {
                return Err(Error::Invalid.into());
            }
        }
        Ok(Self(map))
    }
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
    fn boolean(&self, key: &str) -> ApiResult<bool> {
        match self.get(key) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            _ => Err(Error::Invalid.into()),
        }
    }
    fn number(&self, key: &str, default: usize) -> ApiResult<usize> {
        self.get(key)
            .map(|s| s.parse().map_err(|_| Error::Invalid.into()))
            .unwrap_or(Ok(default))
    }
    fn json(&self, key: &str) -> ApiResult<Option<Value>> {
        self.get(key)
            .map(|s| serde_json::from_str(s).map_err(|_| Error::Invalid.into()))
            .transpose()
    }
    fn read_options(&self) -> ApiResult<ReadOptions> {
        Ok(ReadOptions {
            rev: self.get("rev").map(str::to_owned),
            latest: self.boolean("latest")?,
            revs: self.boolean("revs")?,
            conflicts: self.boolean("conflicts")?,
            revs_info: self.boolean("revs_info")?,
            deleted_conflicts: self.boolean("deleted_conflicts")?,
            all_leaves: match self.get("style") {
                None | Some("main_only") => false,
                Some("all_docs") => true,
                _ => return Err(Error::Invalid.into()),
            },
        })
    }
}
async fn body_json(request: Request, max: usize) -> ApiResult<Value> {
    if request
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v != "identity")
    {
        return Err(Error::Unsupported.into());
    }
    let bytes = tokio::time::timeout(Duration::from_secs(30), to_bytes(request.into_body(), max))
        .await
        .map_err(|_| ApiError::from(Error::Timeout))?
        .map_err(|_| ApiError::large())?;
    super::cpu()?
        .run(move || {
            super::json::preflight(&bytes)?;
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
            super::json::footprint(&value)?;
            if !value.is_object() {
                return Err(Error::Invalid);
            }
            Ok(value)
        })
        .await
        .map_err(ApiError::from)
}
async fn response(status: StatusCode, value: Value, max: usize) -> ApiResult<Response> {
    let bytes = super::cpu()?
        .run(move || {
            super::json::footprint(&value)?;
            Ok(serde_json::to_vec(&value)?)
        })
        .await?;
    if bytes.len() > max {
        return Err(ApiError::large());
    }
    Ok((status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}
async fn dispatch(State(app): State<App>, request: Request) -> Response {
    let head = request.method() == Method::HEAD;
    let mut result = match handle(&app, request).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    if head {
        *result.body_mut() = Body::empty();
    }
    result
}
async fn handle(app: &App, request: Request) -> ApiResult<Response> {
    let who = authenticate(app, request.headers()).await?;
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let query = Query::parse(request.uri().query())?;
    let max = app.couch.options.max_response_bytes;
    if path == "/" && matches!(method, Method::GET | Method::HEAD) {
        return response(
            StatusCode::OK,
            json!({"couchdb":"Welcome","version":"0.2.0","uuid":app.couch.instance().await?,"vendor":{"name":"obsidian-sync","compatibility":"Self-hosted LiveSync CouchDB replication subset"}}),
            max,
        ).await;
    }
    if path == "/_session" && matches!(method, Method::GET | Method::HEAD) {
        return response(
            StatusCode::OK,
            json!({"ok":true,"userCtx":{"name":who.id(),"roles":[]},"info":{"authenticated":"default","authentication_handlers":["default"]}}),
            max,
        ).await;
    }
    let trimmed = path.strip_prefix('/').ok_or(Error::Invalid)?;
    let (db, doc) = trimmed
        .split_once('/')
        .map_or((trimmed, None), |(d, p)| (d, Some(p)));
    let name = decode(db)?;
    if name.starts_with('_') {
        return Err(Error::Unsupported.into());
    }
    let write = matches!(method, Method::PUT | Method::DELETE)
        || (method == Method::POST && matches!(doc, None | Some("_bulk_docs")));
    let (vault, active) = app.couch.resolve_entry(&who, &name, write).await?;
    if !active {
        if method == Method::PUT && doc.is_none_or(str::is_empty) {
            let created = app.couch.activate(&who, &name, vault).await?;
            return if created {
                response(StatusCode::CREATED, json!({"ok":true}), max).await
            } else {
                Ok(StatusCode::PRECONDITION_FAILED.into_response())
            };
        }
        return Err(Error::NotFound.into());
    }
    let Some(raw_doc) = doc.filter(|d| !d.is_empty()) else {
        return match method {
            Method::GET | Method::HEAD => {
                response(
                    StatusCode::OK,
                    wire_sequences(app.couch.info(&who, &name, vault).await?, vault),
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
                app.couch.reset(&who, &name, vault).await?;
                response(StatusCode::OK, json!({"ok":true}), max).await
            }
            Method::POST => {
                let mut value = body_json(request, app.couch.options.max_request_bytes).await?;
                if value.get("_id").is_none() {
                    value["_id"] = json!(Uuid::new_v4().simple().to_string());
                }
                put(app, &who, vault, value, true).await
            }
            _ => Err(Error::Unsupported.into()),
        };
    };
    let id = decode(raw_doc)?;
    match id.as_str() {
        "_revs_diff" if method == Method::POST => {
            response(
                StatusCode::OK,
                app.couch
                    .revs_diff(
                        &who,
                        vault,
                        body_json(request, app.couch.options.max_request_bytes).await?,
                    )
                    .await?,
                max,
            )
            .await
        }
        "_bulk_get" if method == Method::POST => {
            response(
                StatusCode::OK,
                app.couch
                    .bulk_get(
                        &who,
                        vault,
                        body_json(request, app.couch.options.max_request_bytes).await?,
                        query.read_options()?,
                    )
                    .await?,
                max,
            )
            .await
        }
        "_bulk_docs" if method == Method::POST => {
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
                let (length, _, doc) = super::measured(doc).await?;
                let result = if length > app.couch.options.max_document_bytes {
                    Err(ApiError::large())
                } else {
                    app.couch
                        .put(&who, vault, doc, new_edits)
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
            response(StatusCode::CREATED, json!(results), max).await
        }
        "_all_docs" if matches!(method, Method::GET | Method::HEAD | Method::POST) => {
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
                wire_sequences(app.couch.all_docs(&who, vault, options).await?, vault),
                max,
            )
            .await
        }
        "_changes" if matches!(method, Method::GET | Method::HEAD | Method::POST) => {
            let body = if method == Method::POST {
                body_json(request, app.couch.options.max_request_bytes.min(256 * 1024)).await?
            } else {
                json!({})
            };
            changes(app, &who, &name, vault, &query, body).await
        }
        "_ensure_full_commit" if method == Method::POST => {
            app.couch.resolve(&who, &name, true).await?;
            response(
                StatusCode::CREATED,
                json!({"ok":true,"instance_start_time":"0"}),
                max,
            )
            .await
        }
        "_revs_limit" if matches!(method, Method::GET | Method::HEAD) => {
            response(StatusCode::OK, json!(super::MAX_ANCESTRY), max).await
        }
        _ => {
            if id.starts_with('_') && !id.starts_with("_local/") && !id.starts_with("_design/") {
                return Err(Error::Unsupported.into());
            }
            validate_id(&id)?;
            match method {
                Method::GET | Method::HEAD => {
                    let opts = query.read_options()?;
                    let value = if let Some(open) = query.get("open_revs") {
                        let revs = if open == "all" {
                            None
                        } else {
                            Some(
                                serde_json::from_str::<Vec<String>>(open)
                                    .map_err(|_| Error::Invalid)?,
                            )
                        };
                        app.couch.open_revs(&who, vault, &id, revs, opts).await?
                    } else {
                        app.couch.get(&who, vault, &id, opts).await?
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
                    put(app, &who, vault, value, new_edits).await
                }
                Method::DELETE => {
                    let rev = query.get("rev").ok_or(Error::Conflict)?;
                    put(
                        app,
                        &who,
                        vault,
                        json!({"_id":id,"_rev":rev,"_deleted":true}),
                        true,
                    )
                    .await
                }
                _ => Err(Error::Unsupported.into()),
            }
        }
    }
}
async fn put(
    app: &App,
    who: &Identity,
    vault: Uuid,
    value: Value,
    new_edits: bool,
) -> ApiResult<Response> {
    let (length, _, value) = super::measured(value).await?;
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
fn wire_sequences(mut value: Value, vault: Uuid) -> Value {
    for field in ["update_seq", "last_seq"] {
        if let Some(counter) = value.get(field).and_then(Value::as_i64) {
            value[field] = json!(super::sequence(vault, counter));
        }
    }
    if let Some(rows) = value.get_mut("results").and_then(Value::as_array_mut) {
        for row in rows {
            if let Some(counter) = row.get("seq").and_then(Value::as_i64) {
                row["seq"] = json!(super::sequence(vault, counter));
            }
        }
    }
    value
}
fn with_active(mut response: Response, permit: tokio::sync::OwnedSemaphorePermit) -> Response {
    response.extensions_mut().insert(Arc::new(permit));
    response
}
async fn changes(
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
        Some(s) => super::parse_sequence(vault, s)?,
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
        for row in rows{let mut bytes=super::cpu().map_err(std::io::Error::other)?.run(move||Ok(serde_json::to_vec(&row)?)).await.map_err(std::io::Error::other)?;bytes.push(b'\n');yield bytes;}
        let mut bytes=serde_json::to_vec(&json!({"last_seq":last,"pending":pending})).map_err(std::io::Error::other)?;bytes.push(b'\n');yield bytes;
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
