//! Stable, sanitized Couch-compatible error responses.
use crate::Error;
use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};

#[derive(Debug)]
pub struct ApiError {
    pub(super) status: StatusCode,
    pub(super) code: &'static str,
    pub(super) reason: &'static str,
}
impl ApiError {
    pub(super) fn auth() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            reason: "Authentication required",
        }
    }
    pub(super) fn busy() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "too_many_requests",
            reason: "Retry later",
        }
    }
    pub(super) fn large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "request_entity_too_large",
            reason: "Configured transfer limit exceeded",
        }
    }
    pub(super) fn object(&self) -> Value {
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
