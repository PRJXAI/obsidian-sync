//! Exact owner-selected 2026-10-30 stack risks. Never suppress raw findings/errors.
use crate::{Result, ensure, util};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path, sync::OnceLock};
pub const POLICY: &str = "owner-selected-stack-2026-10-30-v1";
fn snapshot() -> Result<&'static Value> {
    static DATA: OnceLock<Value> = OnceLock::new();
    if let Some(v) = DATA.get() {
        return Ok(v);
    }
    let value = util::strict_json(include_bytes!("accepted-risks.json"))?;
    ensure(
        value["schema"] == 1
            && value["decision"] == "owner-selected-stack-2026-10-30"
            && value["inventory_gaps_accepted"] == false
            && value["runtime_findings_accepted"] == false
            && value["new_findings_accepted"] == false,
        "Unsupported risk acceptance",
    )?;
    let _ = DATA.set(value);
    DATA.get().ok_or_else(|| "Missing risk snapshot".into())
}
fn projection(finding: &Value) -> Result<Value> {
    let package = &finding["artifact"];
    let mut paths = package["locations"]
        .as_array()
        .ok_or("Missing finding locations")?
        .iter()
        .map(|v| {
            v["path"]
                .as_str()
                .map(str::to_owned)
                .ok_or("Invalid finding location")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    ensure(!paths.is_empty(), "Empty finding locations")?;
    let mut related=finding["relatedVulnerabilities"].as_array().ok_or("Missing related advisory coverage")?.iter().map(|v|json!({"id":v["id"],"namespace":v["namespace"],"severity":v["severity"],"fix":v["fix"]})).collect::<Vec<_>>();
    related.sort_by_key(Value::to_string);
    let v = &finding["vulnerability"];
    Ok(
        json!({"package":{"name":package["name"],"version":package["version"],"type":package["type"],"locations":paths},"vulnerability":{"id":v["id"],"namespace":v["namespace"],"severity":v["severity"],"fix":v["fix"]},"related":related}),
    )
}
fn decide(profile: Option<&Value>, findings: &[Value]) -> Result<Value> {
    let mut used = BTreeMap::<String, u64>::new();
    let mut accepted = 0usize;
    if let Some(profile) = profile {
        let rules = profile["rules"]
            .as_array()
            .ok_or("Missing accepted-risk rules")?;
        ensure(rules.len() <= 2048, "Risk rule limit")?;
        for finding in findings {
            let identity = projection(finding)?;
            if let Some(rule) = rules.iter().find(|r| r["identity"] == identity) {
                let id = rule["id"]
                    .as_str()
                    .ok_or("Missing acceptance rule identity")?
                    .to_owned();
                let n = used.entry(id).or_default();
                let limit = rule["maximum_occurrences"]
                    .as_u64()
                    .ok_or("Missing acceptance occurrence limit")?;
                ensure(
                    (1..=64).contains(&limit),
                    "Invalid acceptance occurrence limit",
                )?;
                if *n < limit {
                    *n += 1;
                    accepted += 1;
                }
            }
        }
    }
    let blocking = findings.len() - accepted;
    Ok(
        json!({"policy":POLICY,"status":if blocking>0 {"findings"} else if accepted>0 {"accepted-risk"} else {"clean"},"total":findings.len(),"accepted":accepted,"blocking":blocking,"rules":used}),
    )
}
pub fn assess(root: &Path, catalog: &Value, findings: &[Value], scope: &str) -> Result<Value> {
    // Runtime/source content can never inherit a registry or builder exception.
    if matches!(scope, "runtime" | "source") {
        return decide(None, findings);
    }
    let assets = snapshot()?["assets"]
        .as_array()
        .ok_or("Missing accepted-risk assets")?;
    let metadata = &catalog["source"]["metadata"];
    let platform = format!(
        "{}/{}",
        metadata["os"].as_str().unwrap_or(""),
        metadata["architecture"].as_str().unwrap_or("")
    );
    let recipe = if scope == "builder" {
        Some(util::hash(&root.join("Dockerfile"))?)
    } else {
        None
    };
    let profile = assets.iter().find(|p| {
        (catalog["source"]["type"] == "image"
            && p["config_id"].is_string()
            && p["config_id"] == metadata["imageID"]
            && p["platform"] == platform)
            || (scope == "builder"
                && catalog["source"]["type"] == "image"
                && p["asset"] == "populated-builder"
                && p["dockerfile_sha256"].as_str() == recipe.as_deref()
                && p["platforms"]
                    .as_array()
                    .is_some_and(|ps| ps.iter().any(|v| v == &platform)))
    });
    decide(profile, findings)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_snapshot_preserves_findings_and_rejects_changes_duplicates_and_foreign_subjects()
    -> Result {
        let assets = snapshot()?["assets"].as_array().ok_or("assets")?;
        let p = assets
            .iter()
            .find(|p| !p["rules"].as_array().unwrap().is_empty() && p["config_id"].is_string())
            .ok_or("profile")?;
        let rule = &p["rules"][0];
        let mut artifact = rule["identity"]["package"].clone();
        artifact["locations"] = json!(
            artifact["locations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| json!({"path":p}))
                .collect::<Vec<_>>()
        );
        let finding = json!({"artifact":artifact,"vulnerability":rule["identity"]["vulnerability"],"relatedVulnerabilities":rule["identity"]["related"]});
        let decision = decide(Some(p), std::slice::from_ref(&finding))?;
        assert_eq!(decision["total"], 1);
        assert_eq!(decision["accepted"], 1);
        assert_eq!(decision["blocking"], 0);
        assert_eq!(decision["status"], "accepted-risk");
        let copies =
            vec![finding.clone(); rule["maximum_occurrences"].as_u64().unwrap() as usize + 1];
        assert_eq!(decide(Some(p), &copies)?["blocking"], 1);
        for (pointer, value) in [
            ("/vulnerability/id", json!("new")),
            ("/vulnerability/fix/versions", json!(["new-fix"])),
            ("/artifact/version", json!("new-version")),
            ("/artifact/locations/0/path", json!("/different")),
        ] {
            let mut changed = finding.clone();
            *changed.pointer_mut(pointer).ok_or("field")? = value;
            assert_eq!(decide(Some(p), &[changed])?["blocking"], 1);
        }
        assert_eq!(decide(None, std::slice::from_ref(&finding))?["blocking"], 1);
        let (os, arch) = p["platform"]
            .as_str()
            .ok_or("platform")?
            .split_once('/')
            .ok_or("platform")?;
        let catalog = json!({"source":{"type":"image","metadata":{"imageID":p["config_id"],"os":os,"architecture":arch}}});
        let root = crate::root();
        assert_eq!(
            assess(&root, &catalog, std::slice::from_ref(&finding), "registry")?["accepted"],
            1
        );
        for scope in ["runtime", "source"] {
            assert_eq!(
                assess(&root, &catalog, std::slice::from_ref(&finding), scope)?["blocking"],
                1
            );
        }
        for (path, value) in [
            ("/source/metadata/imageID", json!("foreign")),
            ("/source/metadata/architecture", json!("foreign")),
            ("/source/type", json!("directory")),
        ] {
            let mut foreign = catalog.clone();
            *foreign.pointer_mut(path).ok_or("field")? = value;
            assert_eq!(
                assess(&root, &foreign, std::slice::from_ref(&finding), "registry")?["blocking"],
                1
            );
        }
        assert_eq!(decide(None, &[])?["status"], "clean");
        assert_eq!(snapshot()?["inventory_gaps_accepted"], false);
        Ok(())
    }
}
