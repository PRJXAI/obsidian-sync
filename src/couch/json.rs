//! Allocation preflight, NOT a JSON parser: serde_json remains the sole syntax authority.
use crate::{Error, Result};
use serde_json::Value;

pub(super) const HEAP_LIMIT: usize = 16 * 1024 * 1024;
pub(super) const HEAP_PAGE: usize = HEAP_LIMIT - 64 * 1024;
const STRUCTURAL_LIMIT: usize = 65536;

/// Bound token-dense inputs BEFORE constructing a potentially huge serde Value tree.
/// Punctuation inside strings (including escaped quotes/backslashes) is not structural.
pub(super) fn preflight(bytes: &[u8]) -> Result<()> {
    let (mut quoted, mut escaped, mut count) = (false, false, 0);
    for &byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if matches!(byte, b'{' | b'[' | b':' | b',') {
            count += 1;
            if count > STRUCTURAL_LIMIT {
                return Err(Error::TooLarge);
            }
        }
    }
    Ok(())
}
fn charge(total: &mut usize, bytes: usize) -> Result<()> {
    *total = total.checked_add(bytes).ok_or(Error::TooLarge)?;
    if *total > HEAP_LIMIT {
        return Err(Error::TooLarge);
    }
    Ok(())
}
/// Conservative working-set charge, independent of wire bytes. Includes capacity,
/// tree-node/allocator headroom and deliberately overcharges tiny/empty maps.
/// Iterative traversal avoids adding an independent recursive stack limit.
pub(super) fn footprint(value: &Value) -> Result<usize> {
    let mut pending = vec![value];
    let mut total = 0;
    while let Some(value) = pending.pop() {
        charge(&mut total, size_of::<Value>())?;
        match value {
            Value::String(value) => charge(&mut total, value.capacity())?,
            Value::Array(values) => {
                charge(
                    &mut total,
                    values.capacity().saturating_mul(size_of::<Value>()),
                )?;
                pending.extend(values.iter());
            }
            Value::Object(values) => {
                charge(
                    &mut total,
                    1024_usize.saturating_add(values.len().saturating_mul(256)),
                )?;
                for (key, value) in values {
                    charge(&mut total, key.capacity())?;
                    pending.push(value);
                }
            }
            _ => (),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoted_punctuation_is_not_a_token_budget_or_syntax_shortcut() {
        let value = serde_json::json!({"data":"\"\\\\\"[]{}:,".repeat(20000)});
        let bytes = serde_json::to_vec(&value).unwrap();
        preflight(&bytes).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), value);
        // Preflight deliberately does not pretend to validate JSON.
        preflight(br#"{"bad": true false}"#).unwrap();
        assert!(serde_json::from_slice::<Value>(br#"{"bad": true false}"#).is_err());
        assert!(preflight(format!("[{}]", "0,".repeat(STRUCTURAL_LIMIT)).as_bytes()).is_err());
    }
    #[test]
    fn dense_maps_and_array_capacity_are_charged_not_just_wire_size() {
        let value = serde_json::json!([{"x":0}]);
        assert!(footprint(&value).unwrap() > serde_json::to_vec(&value).unwrap().len());
        assert!(
            footprint(&Value::Array(vec![
                Value::Null;
                HEAP_LIMIT / size_of::<Value>()
            ]))
            .is_err()
        );
    }
}
