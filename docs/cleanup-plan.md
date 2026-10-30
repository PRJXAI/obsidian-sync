# Repository assessment and safe simplification plan

Assessment baseline: **2026-10-30**, source `e240ab9`. The original assessment and proposed phases below are retained for comparison. Phases 1–5 have now been implemented on `refactor/behavior-preserving-cleanup`; verification and retained failed attempts are in [results](results.md#cleanup-implementation--2026-10-30). The earlier assessment-only evidence remains [separately attributed](results.md#repository-assessment-and-local-sync--2026-10-30).

## Execution contract

Implementation branch: `refactor/behavior-preserving-cleanup`. Before changing transaction code or shared publication ownership, the intended consistency/security guarantees are **unchanged**: immediate SQLite CAS/replay, body durability before references, reauthorization at publication/replay, first-body-wins imported revisions, retained branches/tombstones, generation fencing, shared bounded upload permits/deadlines and writer-lock lifetime through canceled blocking tasks. Public APIs, CLI/configuration, schema, stored hashes and error classifications remain stable. Only fixture lifecycle error reporting may become stricter: cleanup failures must not report success.

The numbered phases below describe the approved scope. Conditional CI deduplication, dependency upgrades and disk cleanup require evidence/approval and are not automatic parts of the refactor. Desktop acceptance remains a separate manual/UI test.

| Phase | Implementation status |
|---|---|
| 1. Documentation | Corrected unsupported UUID route, retired Kubernetes recommendation and historical public-package wording. |
| 2. Transaction readability | Expanded job, publication/checkpoint and read-selection flows without changing predicates or transaction boundaries. |
| 3. Shared core | Private `blob`/`replay` modules; public `Engine` wrappers and current `Engine.db` behavior retained. |
| 4. HTTP | Private codec/error/database/document/bulk/changes modules; router/middleware/public paths unchanged; characterization tests added before extraction. |
| 5. Fixtures | One private owned-data cleanup helper, explicit checked teardown, Drop fallback and failure/cancellation tests. Eight-cell CI coverage unchanged. |
| 6. Dependencies/cache | Read-only duplicate-tree review completed; no dependency updates or cache/evidence/data deletion justified. |
| Rust organization | Cohesive modules, explicit sibling imports, restricted visibility and stable public re-exports; no new framework/crates/dependencies. See [maintenance](maintenance.md#rust-organization). |

The plan's desktop GUI acceptance remains pending; genuine Commonlib/PouchDB execution is not relabeled as an Obsidian UI run.

## What has been built

This is a working private Rust **Self-hosted LiveSync backend**, not an Obsidian plugin, generic file synchronizer or complete Apache CouchDB replacement. Its minimal runtime is one executable, TOML configuration, local SQLite and filesystem blobs. Node, Docker, scanners and deployment tooling are development/optional deployment dependencies, not requirements for that native runtime.

| Component | Implementation and evidence |
|---|---|
| LiveSync replication | `src/couch/`: revision trees, sibling conflicts, tombstones/resurrection, immutable revision bodies, bulk replication, changes feeds, independent local checkpoints and scoped bootstrap reset/archive. Real Commonlib/PouchDB clients pass against a running server. |
| Identity and isolation | `src/auth.rs`, `src/couch/http.rs`: revocable random device keys, Basic/Bearer authentication, vault grants, separate reset capability, exact CORS, request/admission/feed limits. Negative authorization and race tests pass. |
| Persistence and recovery | `src/db.rs`: SQLite FULL/WAL, schema migration, process writer lock, bounded blocking work, backup/checkpoint. Restart, interruption, backup restoration and migration tests pass. |
| Blob storage | `src/storage/`: shared streaming interface, create-only publication, scoped generated keys and hash/size checking. Filesystem and disposable RustFS/S3 contracts pass; native GCS/Azure verification remains separate. |
| Background work | `src/jobs.rs`: persisted read-only integrity jobs with fenced claims, retry/backoff, quotas and shutdown/restart recovery. |
| Internal CAS core | `src/sync.rs`: legacy single-head mutation API **plus actively shared blob publication/replay helpers**. It is not unused code and must not replace LiveSync's DAG. |
| Operations | `src/main.rs`: offline database/key administration, integrity jobs and backup; bounded HTTP serving and graceful stop. Distroless/nonroot runtime, optional Compose and rendered Kustomize examples. |
| Engineering tooling | `xtask/`: tests, feature matrix, client fixtures, deployment checks, documentation, SBOM/scans, exact accepted-risk accounting and source-bound release tooling. First-party automation is Rust. |

At this revision, `src/` contains **4,606 lines** of Rust and `xtask/src/` **4,882 lines**, including blanks/comments. Tooling is substantial, but line count alone is not evidence that its controls are redundant. The largest runtime files are `src/couch/http.rs` (915 lines) and `src/couch/reads.rs` (596 lines).

Not built/certified: a replacement Obsidian UI, desktop/mobile GUI qualification, full CouchDB administration/Mango/native attachments, multi-writer service, final-object GC, MCP, or provider-native disaster-recovery qualification. LiveSync's chunked binary files are supported; that is distinct from native CouchDB attachments.

## Local end-to-end result

**Passed** `cargo xtask test-livesync`: the real pinned Commonlib 0.1.44/PouchDB 9 clients connected over loopback to a disposable native server. Eleven reported scenarios cover bootstrap recreation, two-peer offline conflicts, concurrent CAS, paginated replication, Unicode note create/read/update/move/delete, a byte-identical 3 MiB attachment, encryption/compression, randomized encrypted replay, Fast Fetch, live changes and persistence after restart.

The same fixture passed against disposable local RustFS/S3 and the static/nonroot container runtime. The harness stopped the server, restarted it on the same backend, verified conflicts/checkpoints/encrypted content, then stopped it again with a successful exit. Post-run checks found no matching server processes, owned fixture containers or fixture directories.

**This was not a sync initiated inside the Obsidian desktop application.** Obsidian was installed, but no desktop UI automation was available through this session's tools. No existing vault was opened or inspected. The successful result covers genuine upstream client libraries and a real server, not plugin UI, Obsidian filesystem-event handling or mobile behavior.

## Findings and proposed changes

### 1. Reconcile the documentation with the implemented contract — low risk

Concrete drift found during source review:

- `docs/llm.md` still recommends “Compose/Kubernetes smokes” immediately before saying live Kubernetes tests are retired. Keep Compose and local manifest rendering; remove the contradictory recommendation.
- `docs/livesync-protocol.md` lists `/_uuids` as implemented. `src/couch/http.rs::handle` special-cases `/` and `/_session`, then rejects other root underscore names with `Error::Unsupported`. Correct the advertised surface; adding a route would be separate feature work, not cleanup.
- `docs/results.md` mixes current public-package success with an older “Until packages are public” condition. Label that sentence as the earlier run's status, without deleting failed evidence or implying Required CI has passed.

Keep the existing operator starting points. Prefer cross-links to the protocol, operations and security contracts over repeating detailed rules across every page. Preserve historical findings, limitations and ownership instructions.

**Exit check:** review each affected claim against source/tests; run `cargo xtask sync-generated`, `cargo xtask docs check` and deployment rendering. Do not acknowledge changed source fingerprints without reading the corresponding source/docs.

### 2. Make transaction code readable before restructuring it — low risk

`src/jobs.rs::{claim,complete,inspect}`, `src/couch/revisions.rs::{put,put_local}` and several `src/couch/reads.rs` queries compress multiple decisions and SQL operations onto single lines. Passing rustfmt does not make these transaction boundaries easy to review.

Expand one transaction at a time into named intermediate values and readable SQL. Initially preserve SQL statements, parameter order, transaction mode, authorization position, commit point and error mapping exactly. Do not combine formatting with query optimization, schema changes or altered retry behavior.

**Exit check:** review the semantic diff; run the workspace tests, especially publication rollback, reset fencing, checkpoint CAS, job claim races, cancellation and backup/restart tests. Expected improvement is auditability, not a promised speedup or smaller line count.

### 3. Separate shared blob publication from legacy CAS semantics — medium risk

`Couch` constructs `sync::Engine`; revision/read paths use its reservation, upload and read methods. Integrity jobs also import `blob_info`, `record` and `replay` from `sync`. Removing the “legacy” module would break current functionality.

First move only shared blob metadata/publication and replay helpers behind a small internal module. Keep `Engine`'s existing public methods as delegating wrappers, with the same shared semaphore and deadline behavior; then let Couch/jobs use the neutral internal implementation. Keep legacy mutations, public imports, CLI commands, schema tables and migration fixtures intact. Consolidate the identical request-key validation in `sync::validate_key` and `Queue::enqueue` only after preserving their boundary tests.

**Exit check:** no public API, CLI, schema or stored replay-hash changes; all core, Couch, migration, storage, interruption and genuine-client tests pass. In particular, normal CAS replay remains payload-bound while imported Couch revisions remain first-body-wins. Any later removal of legacy functionality requires a separately approved deprecation/migration plan.

### 4. Reduce HTTP dispatch complexity in small moves — medium risk

`src/couch/http.rs` combines admission, authentication/rates, decoding, JSON limits, routing and feeds. Its `handle` function spans roughly 286 lines.

Start by extracting private query/body decoding and error-response helpers without replacing the router. Next extract database, document and bulk endpoint handlers one at a time. Move the changes-feed implementation only after those smaller changes pass. Keep a readable dispatch function; do not introduce a generic endpoint framework or replace the current path parser wholesale.

**Exit check:** unchanged status/header/body behavior, escaped/slash-containing IDs, HEAD handling, authorization before authenticated rate charging, preflight and actual-request CORS, byte/structural/aggregate JSON budgets, and response-owned permits. Waiting feeds must still release execution slots. Run all 15 Couch integration tests and the real client fixture after each extraction; add focused regression cases for any uncovered behavior before moving it.

### 5. Simplify fixture ownership, not the test matrix — medium risk

`xtask/src/clients.rs::Server::drop` and `xtask/src/deployment.rs::DataCleanup::drop` repeat the UID-scoped container data cleanup command. Native and container lifecycle paths also share readiness/stop obligations.

Extract just the repeated owned-data cleanup operation, keeping its fixed image, restricted mounts, user, deadlines and cancellation behavior. Keep an explicit checked cleanup path for successful runs and best-effort Drop cleanup for failures. Add negative cleanup/startup/cancellation tests before changing resource ownership. Avoid a new generalized process/container framework.

The eight feature cells repeat tooling tests. Measure CI cost before considering running feature-independent xtask tests once; preserve feature-specific build/release/Clippy/runtime tests in every cell and mandatory aggregate failure on missing/skipped/canceled jobs. Do not adopt this optimization without an equivalence check.

**Exit check:** native, S3 and runtime client fixtures; Compose writer exclusion/stop; cancellation/timeout tests; no owned resources left behind. Preserve locked, genuine upstream client coverage, including the documented fresh-reader workaround for Commonlib's compressed move cache issue.

### 6. Treat dependency/cache cleanup as a separate, measured task — low risk if read-only

`cargo deny check` passes with duplicate-version warnings for `hashbrown`, `syn` and `winnow`; npm reports deprecated transitive LevelDB-family fixtures but zero audited vulnerabilities in this run. These are investigation candidates, not permission to force incompatible versions or change the pinned client contract. Use dependency trees and upstream updates; preserve Cargo/npm lockfiles, feature cells, license gates and fresh audits.

Do not bulk-delete `.work/`: it can contain private evidence, historical failed captures and local operational material. Do not run broad `git clean`, Docker prune, or delete internal backend data. If disk cleanup is later requested, inventory sizes/ownership first and implement an explicit dry-run/allowlist Rust xtask for approved disposable artifacts only. Final blobs/revisions/tombstones/replay records and unarchived evidence stay out of that allowlist.

## Sequence, safety and acceptance

Implement these as separate reviewable changes: documentation → readability → shared-core separation → HTTP extraction → fixture cleanup. Dependency/cache work is optional and independent. Do not implement all phases in one patch.

Before each concurrent-mutation change, write down that the intended consistency/security guarantees are **unchanged**: transactional CAS/replay, durable body-before-reference publication, reauthorization, retained branches/tombstones, generation fencing, bounded admission/work and process-lock lifetime through canceled blocking work. A proposal that changes these is not a cleanup.

For each runtime refactor, retain the existing negative/race/cancellation/restart tests and add characterization coverage before moving uncovered behavior. Run the required check/feature/S3/render gates, genuine native/runtime clients, image/SBOM checks and Compose smoke. Record exact outcomes and omissions in [results](results.md); refresh generated docs and review fingerprints when source changes. No Kubernetes operation or real vault/provider account is part of this plan.

Keep commits independently reversible, with no schema/data migration in the proposed cleanup. Reject a phase if it changes stored bytes/identities, wire behavior, CLI/config compatibility, limits, error classifications or security policy. Revert that code change rather than manipulating retained backend storage. Do not claim performance improvement without a separate idle-host benchmark.

## Remaining desktop acceptance test

To complete the specifically **Obsidian-originated** test, follow [getting started](getting-started.md#5-connect-obsidian) with two newly created disposable desktop vaults and the pinned plugin. Use a separate disposable backend and private key entry, never existing vault credentials. Verify create/edit/delete/move and attachment equality on the peer; include offline competing edits and server restart, then stop the fixture service and close only the test vault windows. Record plugin/Obsidian versions and sanitized pass/fail outcomes. This manual/UI step remains pending; the library fixture must not be relabeled as its completion.
