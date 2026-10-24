use crate::{Result, ensure};
use chrono::{DateTime, Utc};

pub fn fresh(value: &str, now: DateTime<Utc>) -> Result {
    let timestamp = DateTime::parse_from_rfc3339(value)?;
    let age = now.signed_duration_since(timestamp).num_seconds();
    ensure((-300..=86400).contains(&age), "Stale/future evidence")
}
