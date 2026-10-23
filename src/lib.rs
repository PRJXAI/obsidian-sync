//! Private Self-hosted LiveSync-compatible persistence and replication service.
#![forbid(unsafe_code)]
pub mod auth;
pub mod config;
pub mod couch;
pub mod db;
pub mod error;
pub mod jobs;
pub mod storage;
pub mod sync;
pub mod transport;

pub use error::{Error, Result};
