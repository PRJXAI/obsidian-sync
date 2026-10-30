//! Bounded HTTP adapter for the verified LiveSync/PouchDB replication contract.
mod bulk;
mod changes;
mod codec;
mod database;
mod document;
mod error;
use super::Couch;
use crate::{Error, auth::Identity};
use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use codec::{Query, body_json, decode, response};
use document::put;
pub use error::ApiError;
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
    // Invalid credentials must not exhaust the shared budget of authenticated devices.
    // Connection/execution admission still bounds the cost of failed authentication.
    if !rates.global.take(
        app.couch.options.burst,
        app.couch.options.requests_per_minute * 4,
    ) {
        return Err(ApiError::busy());
    }
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
        return database::handle(app, &who, &name, vault, method, request).await;
    };
    let id = decode(raw_doc)?;
    match id.as_str() {
        "_revs_diff" if method == Method::POST => bulk::revs_diff(app, &who, vault, request).await,
        "_bulk_get" if method == Method::POST => bulk::get(app, &who, vault, &query, request).await,
        "_bulk_docs" if method == Method::POST => bulk::put(app, &who, vault, request).await,
        "_all_docs" if matches!(method, Method::GET | Method::HEAD | Method::POST) => {
            bulk::all_docs(app, &who, vault, method, &query, request).await
        }
        "_changes" if matches!(method, Method::GET | Method::HEAD | Method::POST) => {
            let body = if method == Method::POST {
                body_json(request, app.couch.options.max_request_bytes.min(256 * 1024)).await?
            } else {
                json!({})
            };
            changes::handle(app, &who, &name, vault, &query, body).await
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
        _ => document::handle(app, &who, vault, id, method, &query, request).await,
    }
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
