//! Protocol-independent persistence core. No client synchronization protocol is exposed.
#![forbid(unsafe_code)]
pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod jobs;
pub mod storage;
pub mod sync;
pub mod transport;

pub use error::{Error, Result};
