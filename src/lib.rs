//! Private Self-hosted LiveSync-compatible persistence and replication service.
//!
//! [`couch`] owns revision-tree semantics and its HTTP adapter. [`storage`] supplies
//! streaming immutable blobs; private publication/replay modules share durable
//! accounting with [`jobs`] and the historical [`sync`] CAS API. [`db`] remains
//! the single SQLite authority. Repository/release automation lives in `xtask`,
//! not in this runtime crate.
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
