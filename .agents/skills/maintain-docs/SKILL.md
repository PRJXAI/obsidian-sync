---
name: maintain-docs
description: Maintain this repository's authored documentation, remove stale pages safely, refresh generated configuration/source maps, and update LLM context after code changes.
---

# Maintain repository documentation

All first-party tooling and tests must be Rust. Use `cargo xtask`; never execute Python or add inline Python. Shell files are thin launchers. Pinned upstream JavaScript clients are the compatibility-test exception only.

1. Read AGENTS.md, README.md, docs/llm.md, docs/consistency.md and docs/threat-model.md. Check `git diff` and `cargo xtask docs check` for source drift and broken links.
2. Read changed implementation AND tests before writing claims. Preserve the pinned LiveSync contract; distinguish Commonlib/PouchDB fixtures, GUI/mobile, reference CouchDB and real-provider validation.
3. Update the smallest affected authored pages. Create with `cargo xtask docs create docs/topic.md --title 'Topic'`; update with an editor or `cargo xtask docs update docs/topic.md --from-file FILE`. Document verified behavior, state, failure/recovery and limits.
4. Before deleting stale prose, preserve useful content and remove inbound links. Only then use `cargo xtask docs delete docs/stale.md --reason 'Superseded by ...' --yes`. Escapes, symlinks, untracked/dirty deletion and inbound links must be rejected. Never delete based solely on age or an LLM judgment.
5. Update docs/llm.md when ownership, commands, invariants or blocked capabilities change. Record only actual measurements in docs/results.md. Exclude secrets, note content, private identifiers and infrastructure details.
6. Run `cargo xtask sync-generated` for canonical config copies and docs/source-map.md. Never hand-edit generated copies. Fingerprints/maps must exclude ignored operator files.
7. Run `cargo test --locked -p xtask` and deployment rendering. Explicitly review affected authored docs before `cargo xtask docs review --reason 'Describe the implementation and docs actually reviewed'`. This acknowledges review; it does not generate prose or certify correctness.
8. Run `cargo xtask sync-generated --check` and `cargo xtask docs check`. Handoff added/updated/deleted pages and blocked checks. Never bypass drift without review.
