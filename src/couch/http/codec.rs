//! Wire decoding/encoding with independent transfer, structural and heap bounds.
use super::{ApiError, ApiResult};
use crate::{
    Error,
    couch::{cpu, json, reads::ReadOptions},
};
use axum::{
    body::to_bytes,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::{collections::HashMap, time::Duration};

pub(super) fn decode(value: &str) -> ApiResult<String> {
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
pub(super) struct Query(HashMap<String, String>);
impl Query {
    pub(super) fn parse(raw: Option<&str>) -> ApiResult<Self> {
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
    pub(super) fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
    pub(super) fn boolean(&self, key: &str) -> ApiResult<bool> {
        match self.get(key) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            _ => Err(Error::Invalid.into()),
        }
    }
    pub(super) fn number(&self, key: &str, default: usize) -> ApiResult<usize> {
        self.get(key)
            .map(|s| s.parse().map_err(|_| Error::Invalid.into()))
            .unwrap_or(Ok(default))
    }
    pub(super) fn json(&self, key: &str) -> ApiResult<Option<Value>> {
        self.get(key)
            .map(|s| serde_json::from_str(s).map_err(|_| Error::Invalid.into()))
            .transpose()
    }
    pub(super) fn read_options(&self) -> ApiResult<ReadOptions> {
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
pub(super) async fn body_json(request: Request, max: usize) -> ApiResult<Value> {
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
    cpu()?
        .run(move || {
            json::preflight(&bytes)?;
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Invalid)?;
            json::footprint(&value)?;
            if !value.is_object() {
                return Err(Error::Invalid);
            }
            Ok(value)
        })
        .await
        .map_err(ApiError::from)
}
pub(super) async fn response(status: StatusCode, value: Value, max: usize) -> ApiResult<Response> {
    let bytes = cpu()?
        .run(move || {
            json::footprint(&value)?;
            Ok(serde_json::to_vec(&value)?)
        })
        .await?;
    if bytes.len() > max {
        return Err(ApiError::large());
    }
    Ok((status, [(header::CONTENT_TYPE, "application/json")], bytes).into_response())
}
