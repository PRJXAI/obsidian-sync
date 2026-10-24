use crate::{Result, ensure, util};
use serde_json::Value;
use std::{collections::BTreeSet, path::Path};

pub const REPOSITORY: &str = "PRJXAI/obsidian-sync";
pub const REQUIRED_CHECK: &str = "Required CI";
pub fn is_revision(s: &str) -> bool {
    s.len() == 40
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn require_jobs(results: &Value) -> Result {
    let map = results.as_object().ok_or("Missing job results")?;
    ensure(
        map.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["rust", "build", "security", "integration", "sbom"])
            && map.values().all(|v| v == "success"),
        "Every required job must succeed; skipped/canceled/missing is failure",
    )
}
pub fn aggregate() -> Result {
    let needs: Value = serde_json::from_str(&std::env::var("REQUIRED_JOB_RESULTS")?)?;
    let results = needs
        .as_object()
        .ok_or("Missing dependencies")?
        .iter()
        .map(|(key, value)| (key.clone(), value["result"].clone()))
        .collect::<serde_json::Map<_, _>>();
    require_jobs(&Value::Object(results))?;
    println!("Every required CI dependency succeeded");
    Ok(())
}
pub fn readiness(policy: &Value) -> Result<Vec<String>> {
    let map = policy.as_object().ok_or("Missing readiness")?;
    ensure(
        map.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["schema_version", "scope", "reviewer_teams", "milestones"])
            && policy["schema_version"] == 1,
        "Unsupported readiness policy",
    )?;
    let scope = policy["scope"].as_object().ok_or("Missing scope")?;
    ensure(
        scope.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["framework", "data_classification", "deployment_profile"])
            && scope.values().all(|v| {
                v.as_str()
                    .is_some_and(|s| !s.trim().is_empty() && s.len() <= 128)
            }),
        "Owner-approved scope missing",
    )?;
    let teams = policy["reviewer_teams"]
        .as_array()
        .ok_or("Missing teams")?
        .iter()
        .map(|v| {
            v.as_str()
                .map(String::from)
                .ok_or_else(|| "Invalid team".into())
        })
        .collect::<Result<Vec<_>>>()?;
    let pattern = regex::Regex::new(r"^@PRJXAI/[a-z0-9][a-z0-9-]{0,99}$")?;
    ensure(
        !teams.is_empty()
            && teams.iter().collect::<BTreeSet<_>>().len() == teams.len()
            && teams.iter().all(|t| pattern.is_match(t)),
        "Approved organization teams missing",
    )?;
    let milestones = policy["milestones"]
        .as_object()
        .ok_or("Missing milestones")?;
    ensure(
        milestones.keys().cloned().collect::<BTreeSet<_>>()
            == (0..8).map(|n| format!("M{n}")).collect(),
        "Missing acceptance milestone",
    )?;
    for value in milestones.values() {
        let fields = value.as_object().ok_or("Invalid milestone")?;
        ensure(
            fields.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["state", "evidence_sha256"])
                && value["state"] == "verified",
            "Open/deferred/waived milestone",
        )?;
        ensure(
            value["evidence_sha256"].as_array().is_some_and(|items| {
                !items.is_empty()
                    && items.iter().all(|v| {
                        v.as_str().is_some_and(|s| {
                            s.len() == 64
                                && s.bytes()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                        })
                    })
            }),
            "Missing independently reviewed closure evidence",
        )?;
    }
    Ok(teams)
}
pub fn codeowners(text: &str, teams: &[String]) -> Result {
    let mut default = false;
    for line in text.lines() {
        let words = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect::<Vec<_>>();
        if words.is_empty() {
            continue;
        }
        ensure(
            words.len() >= 2 && words[1..].iter().all(|v| teams.iter().any(|t| t == v)),
            "Empty/unapproved ownership override",
        )?;
        default |= words[0] == "*";
    }
    ensure(default, "Ownership must cover all source")
}
pub fn controls(
    branch: &Value,
    rules: &Value,
    rulesets: &[Value],
    environment: &Value,
    permissions: &Value,
) -> Result {
    ensure(branch["protected"] == true, "Unprotected source")?;
    let rules = rules.as_array().ok_or("Unreadable branch rules")?;
    for kind in [
        "pull_request",
        "required_status_checks",
        "deletion",
        "non_fast_forward",
    ] {
        ensure(
            rules.iter().any(|v| v["type"] == kind),
            "Missing enforced source rule",
        )?;
    }
    let review = &rules
        .iter()
        .find(|v| v["type"] == "pull_request")
        .ok_or("Missing review")?["parameters"];
    ensure(
        review["required_approving_review_count"]
            .as_u64()
            .is_some_and(|n| n >= 1)
            && [
                "dismiss_stale_reviews_on_push",
                "require_code_owner_review",
                "require_last_push_approval",
                "required_review_thread_resolution",
            ]
            .into_iter()
            .all(|key| review[key] == true),
        "Insufficient review controls",
    )?;
    let checks = &rules
        .iter()
        .find(|v| v["type"] == "required_status_checks")
        .ok_or("Missing checks")?["parameters"];
    ensure(
        checks["strict_required_status_checks_policy"] == true
            && checks["required_status_checks"]
                .as_array()
                .is_some_and(|v| {
                    v.iter()
                        .any(|v| v["context"] == REQUIRED_CHECK && v["integration_id"] == 15368)
                }),
        "Aggregate must be mandatory and bound to GitHub Actions",
    )?;
    let ids = rules
        .iter()
        .map(|v| v["ruleset_id"].as_u64().ok_or("Missing ruleset ID"))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
    let actual = rulesets
        .iter()
        .filter_map(|v| v["id"].as_u64())
        .collect::<BTreeSet<_>>();
    ensure(
        !ids.is_empty()
            && ids == actual
            && rulesets.iter().all(|v| {
                v["enforcement"] == "active"
                    && v["bypass_actors"].as_array().is_some_and(Vec::is_empty)
            }),
        "Unreadable/inactive/bypassable rulesets",
    )?;
    let reviewers = environment["protection_rules"]
        .as_array()
        .ok_or("Missing environment protections")?
        .iter()
        .filter(|v| v["type"] == "required_reviewers")
        .collect::<Vec<_>>();
    ensure(
        environment["can_admins_bypass"] == false
            && reviewers.len() == 1
            && reviewers[0]["prevent_self_review"] == true
            && reviewers[0]["reviewers"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
        "Independent non-bypassable release approval missing",
    )?;
    ensure(
        environment["deployment_branch_policy"]["protected_branches"] == true
            && environment["deployment_branch_policy"]["custom_branch_policies"] == false,
        "Release environment not bound to protected source",
    )?;
    ensure(
        permissions["default_workflow_permissions"] == "read"
            && permissions["can_approve_pull_request_reviews"] == false,
        "Unsafe default workflow token",
    )
}
fn github(root: &Path, path: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&util::output(
        &mut util::cmd(
            "gh",
            &[
                "api",
                "--hostname",
                "github.com",
                &format!("repos/{REPOSITORY}/{path}"),
            ],
            root,
        ),
        60,
    )?)?)
}
pub fn preflight(root: &Path, revision: &str) -> Result {
    ensure(is_revision(revision), "Invalid revision")?;
    let teams = readiness(&util::json(&root.join(".github/security-readiness.json"))?)?;
    codeowners(
        &String::from_utf8(util::read(&root.join(".github/CODEOWNERS"), 65536)?)?,
        &teams,
    )?;
    let branch = github(root, "branches/main")?;
    ensure(
        branch["commit"]["sha"] == revision,
        "Source is no longer current main",
    )?;
    let rules = github(root, "rules/branches/main")?;
    let mut rulesets = Vec::new();
    for id in rules
        .as_array()
        .ok_or("Missing branch rules")?
        .iter()
        .map(|v| v["ruleset_id"].as_u64().ok_or("Invalid ID"))
        .collect::<std::result::Result<BTreeSet<_>, _>>()?
    {
        rulesets.push(github(root, &format!("rulesets/{id}"))?);
    }
    let environment = github(root, "environments/security-release")?;
    controls(
        &branch,
        &rules,
        &rulesets,
        &environment,
        &github(root, "actions/permissions/workflow")?,
    )?;
    for rule in environment["protection_rules"]
        .as_array()
        .ok_or("Missing protections")?
    {
        if rule["type"] == "required_reviewers" {
            for reviewer in rule["reviewers"].as_array().ok_or("Missing reviewers")? {
                ensure(
                    reviewer["type"] == "Team"
                        && reviewer["reviewer"]["slug"]
                            .as_str()
                            .is_some_and(|slug| teams.contains(&format!("@PRJXAI/{slug}"))),
                    "Unapproved release reviewer",
                )?;
            }
        }
    }
    println!("Read-only policy preflight passed; this is not signing or compliance certification");
    Ok(())
}
