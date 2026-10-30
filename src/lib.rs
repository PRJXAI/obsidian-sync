//! Private Self-hosted LiveSync-compatible persistence and replication service.
#![forbid(unsafe_code)]
pub mod auth;
mod blob;
pub mod config;
pub mod couch;
pub mod db;
pub mod error;
pub mod jobs;
mod replay;
pub mod storage;
pub mod sync;
pub mod transport;

pub use error::{Error, Result};
