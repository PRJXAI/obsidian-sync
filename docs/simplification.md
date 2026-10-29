# Simplification checklist

Goal: less code and fewer concepts, without weakening correctness or security. Work through one small, reviewed change at a time; do not introduce a replacement framework or compress code just to reduce line count.

## Tasks

- [x] S01 — Remove external CouchDB tooling; reuse existing in-process HTTP fixtures. Commit `53b3d79`.
- [x] S02 — Retire unused supplier rebuilds and the candidate-image override. Net 915 Rust lines removed. Commit `f6fcd95`.
- [ ] S03 — Audit dead code, CLI options and unnecessary public helpers. Delete only items with no required caller or supported use; otherwise keep them.
- [ ] S04 — Simplify client fixture setup in `xtask/src/clients.rs`, one function at a time. Preserve native, S3 and runtime-image scenarios, loopback restrictions, restart and cleanup.
- [x] S05 — Review command wrappers in `xtask/src/util.rs`. Retain them: capture, decoding, private logging, status handling and cancellation-safe cleanup have distinct semantics.
- [ ] S06 — Review `src/couch/http.rs` and `src/couch/reads.rs` one endpoint at a time. Simplify unnecessary nesting/parsing without changing the wire contract or resource bounds.
- [ ] S07 — Remove dependencies/features proven unnecessary after the code deletions. Update the lockfile and inventory only when justified.
- [ ] S08 — Remove obsolete instructions and duplicate operational steps. Regenerate documentation maps and review fingerprints; preserve historical evidence.

## Reviewed candidates

Reviews used `gpt-6.1-sol` with high thinking. Findings are proposals, not proof of completed cleanup or security acceptance.

- S03: `security::recorded_command` has only two test callers; `sbom::scan` has only module-local callers. Consider reducing production API surface, but do not merely move code to claim fewer lines.
- S04: a borrowed-path micro-optimization was not integrated because its proposed regression scaffold outweighed the implementation reduction. No broader client rewrite is justified yet.
- S06: remove the document PUT object check only after proving `body_json` already rejects non-objects and extending malformed-PUT coverage. Separately verify the unreachable `_all_docs` fallback against live, tombstoned and missing-key responses.
- S07: the first bounded step removes reqwest's unused `json` feature from `xtask/Cargo.toml` and only its two lockfile dependency edges. Independent xtask tests/checks validate the change without workspace feature unification. Broader dependency review remains open; no whole direct-dependency removal was justified.

## Execution rules

- Parallel sub-agents may inspect separate areas; only one implementation change is integrated at a time. Use `pi -p --provider openai-codex --model gpt-6.1-sol --thinking high`.
- Each proposal names current callers, preserved behavior, concrete deletions and regression checks. A review may conclude that no change is warranted.
- Keep authorization, SQLite authority, revision trees/checkpoints, streaming integrity, bounded work and fail-closed security gates. Do not remove tests to make a cleanup pass.
- Validate each change, record actual outcomes in [results](results.md), update affected docs and commit separately. Failed checks remain failures; later passes do not erase them.
- Stop at a review checkpoint before the next implementation step. Checked tasks describe the bounded work above, not a claim that the entire repository is optimally simple.

Reviewed backlog: only the checked items and the bounded reqwest feature step above are implemented. Other proposals remain unimplemented; [results](results.md) records executed checks and outstanding failures.
