# LiveSync implementation evidence

## Syft → SBOM → Grype trial/adoption — 2026-10-24

The [Rust SBOM-first path](scanner-pipeline.md) was executed, not just configured. Syft 1.55.0 generated native JSON, SPDX and CycloneDX for source/runtime/builder (nine inventories); Grype 0.121.0 consumed the native SBOMs offline. Tool images are digest-pinned and Grype's own image is included in scanning. DB retrieval is separate from offline matching. Per-invocation output scratch prevents a writable alias to the SBOM or prior evidence. Tool JSON remains bounded (64 MiB/two million structural tokens); server HTTP limits are unchanged.

| Check | Actual result |
|---|---|
| Rust tooling tests / Clippy | PASS: **44 tests** (36 general, six Grype/transition, two cancellation/subprocess); workspace Clippy `-D warnings` |
| Full local regression/deployment rerun | PASS: `scripts/check.sh`, all eight feature subsets, real S3/reference fixtures, fresh Linux/musl Docker tests, static/nonroot image verification, actual runtime client restart, Compose, disposable kind and rendering; fresh RustSec/deny and source/history Gitleaks |
| Native/CDX source completeness | PASS: all 292 registry Rust packages and all 129 npm lock entries, including workspace/development dependencies |
| Grype source / runtime | PASS: **0 / 0 effective matches** |
| Grype populated builder | **FAIL: 19 effective matches — one Critical, six High, twelve Medium**; all remain under investigation |
| Runtime content binding | PASS: bound native SBOM/report hashes, config/layers and immutable daemon identity verified; not release authorization |
| Declared/comparison images, linux/amd64 | All **11** cataloged/scanned; **10** with matches, zero catalog/scan errors; gate exit 1 retained |
| CouchDB Java inventory | PASS: 126 Java archive packages cataloged; Grype scanned the SBOM without a separate Trivy Java DB download |
| Findings ledger | PASS as inventory only; no advisory waiver, all matches under investigation |
| Same-config baseline comparison | **FAIL / reconciliation pending:** 27 Trivy-only asset/advisory pairs (21 distinct IDs); aliases included and no baseline asset omitted |
| Scanner-transition gate | Explicitly blocked in `.github/scanner-transition.json`; a candidate clean report cannot erase unreconciled baseline findings |

The builder matches include `perl 5.42.2-r1` / `CVE-2026-8376` (Critical), binutils and BusyBox associations. Trivy's earlier zero does not disprove them, nor does Grype establish exploitability or absence of distro backports. Counts are detector/data associations requiring independent exact-binary/platform review. Raw data: ignored `.work/sbom/`, `.work/security/sbom-chain/amd64/`, `.work/grype-trial/`.

Grype's cold DB retrieval succeeded inside the standard **3 GiB memory / 1536 MiB tmpfs** profile; its installed database occupied about **3.1 GiB disk**. This avoids the separate Java DB path, but is not a tiny/no-database scanner or a general speedup claim. Explicit comparison-only Trivy remains available: a cold CouchDB scan reproduced `no space left on device` with 1536 MiB scratch; bounded 5 GiB memory / 3 GiB scratch completed with **356 retained findings**, not a clean result. No Java analysis or severity was disabled.

Default CI now generates SBOMs before Grype scans them; Trivy is no longer executed by the default path. Its comparison pin/baseline remains conservatively inventoried, and transition closure requires independent evidence. Current image findings, the 27 baseline-only pairs, private durable raw-evidence archival and the other acceptance blockers remain OPEN. These local receipts describe a dirty adoption snapshot, not a signed/clean-commit release certification or successful remote run of this new pipeline. No real vault, cloud account, cluster or image publication was used.

### Remote SBOM-first verification

[Run 40110455636](https://github.com/PRJXAI/obsidian-sync/actions/runs/40110455636), commit `2569909`: all eight Rust jobs, shared Linux build/tests/image verification, and nine-format SBOM/materials generation passed. Security passed fresh Cargo audit/deny, all tooling tests, documentation/source checks, minimized source/history secret scans and the bound Grype runtime content check. Grype returned **source 0 / runtime 0 / builder 19**; all **11** image catalogs/scans and the ledger completed, **10** images had matches and **zero scan errors** were reported. The candidate/transition gates and `Required CI` correctly failed; no default Trivy execution or Java DB retrieval was used.

That run's integration job also failed separately in the genuine reference-CouchDB client fixture: Commonlib reported `Direct database version or features are not compatible` during encrypted initialization, after earlier reference scenarios passed. Later integration steps were skipped in this run; they are not claimed passed remotely here. The local final reference/runtime/Compose/kind checks and the complete earlier remote integration run passed, but this new failure remains recorded for investigation rather than hidden by a retry or test removal. Overall CI is **FAILED**, not a release receipt.

## Rust tooling migration — 2026-10-24

First-party tooling/infrastructure tests moved to the Rust `xtask/` workspace crate; Python implementations were removed and shell scripts became thin launchers. npm/Node remain only the pinned upstream JavaScript client bridge. No server schema, protocol, authorization, storage publication or retention logic changed. The egress sandbox is explicitly deferred.

Final local disposable verification, after cancellation, permission and harness fixes:

| Check | Actual result |
|---|---|
| `scripts/check.sh` | PASS: debug/release, fmt, workspace Clippy, **42 active server tests + 37 tooling tests**, three provider tests ignored, fresh audit/deny, generated/docs checks |
| `scripts/check-features.sh` | PASS: all eight feature subsets, debug/release, workspace Clippy/tests |
| `cargo test --locked -p xtask` | PASS: **35 regressions + two cancellation/subprocess tests**; no Python harness |
| Native/filesystem and RustFS/S3 Commonlib/PouchDB fixtures | PASS, including real S3 conditional-create/streaming contract and clean client/server restart |
| Reference CouchDB 3.5.3 | PASS: same genuine client fixture |
| Linux/musl Docker test target | PASS with test-stage cache explicitly disabled; includes all 37 Rust tooling tests |
| Runtime image verification and real-client image fixture | PASS: only static `/server`, UID/GID 65532, actual encrypted/bootstrap/restart workload |
| Build-context canaries | PASS: public inputs retained; synthetic environment/TOML/Cargo-credential/data/node_modules inputs excluded |
| Fresh Cargo audit / deny / npm audit | PASS: **294 locked crate dependencies**, 1,352 RustSec advisories; licenses/bans/sources pass, visible duplicate-version warnings; npm zero findings |
| Source/history Gitleaks and runtime/populated-builder Trivy | PASS: zero secret/runtime/builder findings; caller UID, bounded read-only scanner roots and isolated bare mirror |
| Complete arm64 supply-chain scan | **FAIL (exit 1)**: all ten images produced reports, seven upstream image groups have findings; no missing-report/setup failure was converted into a pass |
| Local artifact/platform findings ledger | PASS as triage inventory only: ten images, all findings under investigation, native review pending; no waiver or release approval |
| SPDX/CycloneDX/materials | PASS: six inventories, native identity, **292 registry Rust packages + all 129 npm lock entries**, original runtime/builder archive-byte binding |
| Deployment rendering, disposable Compose and kind | PASS: private probes, expected second-writer denial, graceful stop, PVC-backed restart; explicit temporary kubeconfig, not CNI enforcement |
| CI aggregate / read-only policy guard | PASS: successful synthetic dependencies accepted; skipped security and unconfigured policy each rejected with exit 1 |
| actionlint 1.7.12, docs/source-map and diff checks | PASS locally; not a successful remote Actions receipt |
| Core and genuine-client benchmark entrypoints | PASS as tooling smoke only; raw measurements remain ignored, no capacity/speedup claim |

The port initially checked only stderr for writer-lock denial; disposable Compose/kind exposed that the classified tracing error can be on stdout. The Rust check now requires a nonzero exit **and** the expected classification on either stream, matching the original combined-stream check. A regression rejects success and unrelated failures. Both real smokes passed after the fix.

This is a **dirty migration snapshot** based on `84ae0e0`, explicitly recorded as dirty in materials, not a signed/clean-commit release receipt. Scanned runtime OCI identity: `sha256:dab8b904cc3de7fdf995450eeb22e6b9394ad7e365db4911225fd9eb1a6e418d`; saved configuration: `sha256:2a021d8f0d95615ff1f844eac90d2efbc0e1aae0df3942ed566d1db2b2603b6b`. Trivy DB updated **2026-10-24 07:11:13 UTC**; RustSec commit `21d909e4c8bd4e14c7aea58bf980c881a0053ab1`. Raw receipts stay in ignored `.work/rust-tooling/`, `.work/security/` and `.work/sbom/`.

Full supply-chain scanning remains failed, with native applicability unresolved. Regenerate clean-commit evidence for release use. No image publication, real cloud account, vault or production cluster was used.

A Docker build-context canary reproduced how allowing a parent directory can re-include private children. Explicit nested child-deny/public-file exceptions now exclude synthetic environment, local TOML, Cargo-credential, data and node_modules canaries while preserving required public inputs. No real operator file was opened for this test.

### First remote migration run

[Run 40099216841](https://github.com/PRJXAI/obsidian-sync/actions/runs/40099216841), commit `7c7d37d`: all eight Rust jobs, shared Linux build/tests/image verification and SBOM job passed. Security passed fresh Rust/secret/runtime/builder scans and content binding; all client/S3/reference/Compose tests passed. The workflow nevertheless **failed**: Kubernetes attempted post-restart execution while the replacement pod was Running but its container was not ready, and amd64 ledger generation rejected scan evidence. `Required CI` correctly rejected the workflow. The Kubernetes fix strengthens the wait to pod Ready; report-size/exit/validation diagnostics were added without publishing raw output. A local amd64 rerun produced all ten reports and a complete ledger while retaining the seven-image vulnerability failure; the validation failure was not treated as a clean scan. [Run 40101883009](https://github.com/PRJXAI/obsidian-sync/actions/runs/40101883009), commit `2a6c7ca`, then passed all eight Rust jobs, shared build, complete integration including corrected Kubernetes readiness, and SBOM generation. Classified diagnostics traced the remaining missing report specifically to CouchDB; the cold Java DB scratch failure and bounded comparison fix are documented above. The workflow and required aggregate correctly remained failed.

`Required CI` now aggregates every producer fail-closed. Public security artifacts contain allowlisted count/status summaries only; raw reports/ledgers stay local pending an approved durable private archive. Source/release protection, reviewer teams, signed authorization, audit policy, crypto/retention and provider/operational acceptance remain blocked. None is implied by the language migration.

## Historical audit/remediation baseline — 2026-10-23

**Expanded supply-chain gate: FAILED / release acceptance blocked.** The subsequent [security audit](security-audit.md) fixed unauthenticated rate-budget depletion, refreshed 14 Rust dependencies and pinned build/test/tool images, and added shared CI image artifacts, runtime-to-release content verification and complete source/runtime/builder SBOM/materials generation. Runtime and populated-builder scans are clean; current official test/scanner/frontend images still have unresolved package findings. No severity/advisory exceptions were added. The implementation evidence below predates this expanded gate and is not an all-supply-chain clean claim.

Remediation verification (2026-10-23, disposable local arm64):

| Check | Actual result |
|---|---|
| `scripts/check.sh`; all eight subsets via `scripts/check-features.sh` | PASS: default **42 active Rust tests**, 3 provider tests ignored; debug/release, fmt, Clippy, fresh RustSec/deny |
| Python regression/maintenance tests | PASS: **19 tests**, including image-content substitution/stale evidence, SBOM dev-lock completeness, unpinned image rejection, scanner cancellation cleanup, LLM guide links, ignored-configuration privacy and caller-identity enforcement for both shell Trivy invocations and ignored-canary isolation in an independent bare Git history snapshot |
| Native and final-runtime Commonlib/PouchDB; S3/RustFS contract/client fixture | PASS, including restart; no real vault/provider account |
| Reference CouchDB | PASS against updated digest-pinned **3.5.3** |
| Linux/musl Docker test target; static/nonroot image verification | PASS |
| Compose/Kustomize rendering; Compose smoke; disposable kind | PASS: **kind 0.33.0 / Kubernetes 1.37.0**, dedicated kubeconfig (inherited disposable sentinel remained byte-for-byte unchanged), PVC restart and lock exclusion; not CNI enforcement |
| Fresh runtime and populated-builder Trivy, RustSec/deny, source/history Gitleaks, npm audit | PASS within their scopes; no runtime/builder package findings or Rust/npm advisories |
| Legacy arm64 supply-chain scanner (now `cargo xtask scan-supply-chain`) | **FAIL (exit 1)**: complete 10-image inventory, findings remain in 7 upstream image pins; exact counts/scope in [audit](security-audit.md) |
| Workflow actionlint 1.7.12 | PASS; local validation does not assert a successful remote GitHub Actions run |
| Legacy SBOM generator (now `cargo xtask generate-sbom`) | PASS: six SPDX/CycloneDX files, native-toolchain identity and `materials.json`; source graph includes all **287 registry Rust dependencies and 129 locked npm dependency entries**, including test dependencies |
| Legacy runtime-content verifier (now `cargo xtask verify-release`) | PASS against the exact fresh scanned runtime; negative config/layer/stale/UNKNOWN tests pass |

Exact locally rebuilt runtime OCI index: `sha256:7893527e4e4956f1c68376842855e84f66f63a7bb95fa1d774599d46acc53c64`; exported configuration: `sha256:c9cd12708a9dc6ce2d12ac14bf5acae8c8a211d41b5e160441ea74b6c07a85b6`. These image measurements came from a pre-publication remediation source snapshot, not a release certification. Regenerate release evidence against the committed source. Scanner DB: Trivy 0.76.1, updated 2026-10-23 07:12:39 UTC; RustSec 1,350 advisories at `f7b2f6bc663452200bbe639ebb75e0c762b3422b`. Raw evidence: ignored `.work/security-audit/`, `.work/security/`, `.work/sbom/`.

No speedup, wire-performance or production-rollout claim is made by this remediation. Machine-specific benchmark profiles and deployment-specific receipts are excluded from this document. Native GCS/Azure, production ACL/CNI/DR and full GUI/mobile checks remain outstanding. SBOM/materials and content verification are unsigned; trusted CI/operator delivery remains required.

## Linux scanner permissions regression

The first published workflow run on the amended source passed all eight Rust feature jobs, Linux build/tests, integration and SBOM generation, but failed security scanning with `mkdir /cache/db: permission denied`. Root with all capabilities dropped could not write runner-owned bind mounts; this was a scanner setup failure, not a successful vulnerability assessment.

Both shell Trivy invocations and the Python supply-chain scanner now use the caller's numeric UID/GID and `HOME=/tmp`. Capability dropping, no-new-privileges, socket isolation and fail-on-findings policy remain unchanged. Offline regressions validate identity/restrictions for database, runtime, builder and per-image commands. A disposable Linux-backed volume smoke reproduced the old root/cap-drop denial and verified that a simulated non-root owner could create the cache and write a Trivy version report with all capabilities still dropped. No credentials, real data or host permission changes were involved. Remote verification on commit `500bb76` completed in [GitHub Actions run 40079991599](https://github.com/PRJXAI/obsidian-sync/actions/runs/40079991599): all eight Rust jobs, Linux build/tests, integration and SBOM jobs passed. The security job's runtime/builder scanning and release-content verification steps passed with zero runtime/builder findings. All ten amd64 supply-chain images produced vulnerability counts, with zero scanner/infrastructure failures or permission errors; seven images failed on findings. The overall workflow therefore remains failed on the intended upstream-image gate, not cache ownership. These upstream findings remain blocking.

## Regulated-data assessment and scanner input isolation

A follow-up [assessment](regulated-security-assessment.md) found that image findings need platform/function/source-version triage and do not establish malicious exfiltration. It also confirmed control gaps relevant to regulated use: unprotected main/zero repository rulesets, broad cloud egress templates, no complete first-party security audit trail and unsigned/runtime-only release evidence. No production settings or real data were inspected or changed.

The history scanner formerly mounted the whole checkout, exposing ignored operator files to the tool. It now receives an independent bare mirror, removes origin configuration, and scans all reachable refs. Synthetic ignored `.env`/data canaries and a detached HEAD regression passed; actual source/history scanning with the mirror completed with zero secret findings. No real-data transmission or exfiltration feature was implemented. Remaining issues and acceptance requirements are documented rather than hidden behind advisory exceptions.

## Acceptance scope

**LiveSync server phase implemented and verified with actual pinned upstream clients.** Target: Self-hosted LiveSync 1.0.39 (source pin in [protocol contract](livesync-protocol.md)), Commonlib 0.1.44 and PouchDB 9.0.0. This is a Rust CouchDB-compatible subset, not Apache CouchDB or a replacement client/UI. MCP remains deferred. GUI/mobile certification and separately authorized production/provider gates below are NOT implied. The implementation checks below used disposable resources without modifying real vaults/cloud accounts; no image was published.

Implemented: persistent revision DAG/conflicts/tombstones/history, ancestry-aware latest reads, bulk replication, bounded incremental/long-poll/NDJSON feeds, local checkpoints, opaque epoch-bound cursors, scoped bootstrap archive/reset/recreate, shared revocable Basic/Bearer credentials and per-vault grants; immutable verified bodies behind filesystem/S3/native GCS/Azure; bounded HTTP/JSON/CPU/I/O execution, quotas and jobs; schema-v3 migration/backup/recovery, static distroless/nonroot runtime and private deployments. Legacy internal CAS remains separate from wire revision trees.

## Initial implementation gates (before the expanded audit)

| Check | Actual result |
|---|---|
| Debug/release builds, fmt, all-target Clippy `-D warnings` | PASS |
| Default Rust tests | PASS: **41 active**, 3 provider tests ignored by default |
| All eight Cargo feature subsets | PASS: debug AND release builds, all-target Clippy, tests; filesystem always enabled |
| Real Commonlib/PouchDB, native Rust/filesystem | PASS, including clean shutdown/restart and encrypted content recovery |
| Real local RustFS | PASS: ignored S3 contract explicitly run (conditional races, 8 MiB streaming); same real-client fixture over S3-backed Rust including restart |
| Reference Apache CouchDB 3.5.0 | PASS: identical client fixture against disposable digest-pinned reference server |
| Final non-root distroless image, real upstream clients | PASS: same HTTP/client workload, bootstrap and restart against the actual rebuilt runtime |
| Linux arm64/musl Docker test target | PASS: debug/release, fmt, Clippy and 41 active tests (3 providers ignored) |
| Python maintenance tests | PASS: 3 lifecycle/drift/link/deletion/traversal/symlink tests |
| Compose + Kustomize base/filesystem/S3/GCS/Azure | PASS: render; overlays also API-server dry-run in disposable kind |
| Compose smoke | PASS: private 204 probes, runtime second-writer exclusion, graceful stop |
| Disposable Kubernetes smoke | PASS: v1.36.1 kind, PVC-backed pod restart, readiness, lock exclusion; explicit isolated kubeconfig |
| Static runtime/image verification | PASS: no ELF interpreter, UID/GID 65532, only `/server` added; no shell/package manager |
| Dependency/secret/runtime scans | PASS, exact scope and identifiers below |

Actual client scenarios: two independently authenticated offline devices/branches and convergence; simultaneous parent-CAS updates; historical/conflicting/deleted revisions; selectors and pagination; checkpoints and repeated replication; Unicode notes, updates, logical deletion/moves; 3 MiB chunked binary bytes; actual E2EE/compression and encrypted replay; actual upstream Fast Fetch, continuous NDJSON and live long-poll wakeup; first-device destroy/recreate; restart with branches, cursor/checkpoint and decryption of the durable moved encrypted note.

Additional Rust evidence: cross-vault/read-only/revoked/wrong-username rejection, strict malformed/unsupported requests and Origin checks, body/document/batch/rate budgets; queued bursts and upload backpressure; token-dense JSON rejection BEFORE allocation and aggregate-tree memory-limited change pagination without skipped cursors; interrupted publication and immutable storage races; static/actively swapped symlink escapes; canceled blocking tasks retaining writer authority; fenced job claims/recovery/fairness/retry/quotas; schema-v1/v2 upgrades and newer-schema rejection; real SQLite backup plus copied filesystem bodies restored into a fresh installation with auth, current epoch/checkpoint, archive and content verification (post-snapshot future cursor rejected). Two core path property tests remain.

These are process/cancellation/interruption tests, not physical power-loss, kernel/disk fault-injection, multi-host writer or production CNI certification. CI commands were exercised locally; their results do not establish a successful remote GitHub Actions run.

## Differential findings and fixes

- **Randomized encrypted replay:** Commonlib encrypts an identical revision again with fresh IV/salt. Apache CouchDB acknowledges replay and retains the first body; bytewise rejection broke Rust replication. Rust now preserves/verifies that first immutable body, never overwrites it, and still rejects contradictory ancestry. Internal explicit idempotency keys remain payload-bound; staging keys include body digest.
- **Opaque checkpoints:** reference CouchDB may return textually different sequence tokens at the same position. Fixtures resume from the checkpoint and verify no outstanding changes, rather than comparing a later info token literally.
- **Shutdown:** stopping worker and feeds could race the server select and falsely exit with failure. Intentional worker completion after the shared shutdown signal is now normal; unexpected worker exit remains fatal. Actual process/container restart fixtures verify exit status.
- **Capacity:** eight logical writers exposed false storage-quota failures at the upload gate and transient immediate admission rejection. Uploads now wait within one operation deadline; normal HTTP work has an explicitly bounded one-second admission queue. No transfer/concurrency/rate/durability limit was disabled to make the workload pass.
- **JSON allocation:** transfer-byte limits alone permit token-dense DOM amplification. Structural preflight, a separate conservative working-set charge, aggregate read construction limits and resumable heap-limited change pages now constrain this path; serde remains the syntax parser.
- **Upstream cache limitation:** Commonlib 0.1.44's warm compressed-chunk cache can return compressed markers after a move on BOTH Apache CouchDB and Rust. Durable content is verified through a fresh reader and after restart; no server-side ciphertext rewrite hides the client issue.

## Security evidence

- `cargo audit` 0.22.1: **0 unresolved advisories/warnings**, 288 locked dependencies. RustSec: **1,350 advisories**, commit `f7b2f6bc663452200bbe639ebb75e0c762b3422b`, updated **2026-10-23 08:19:48 UTC**.
- Fresh scans discovered **RUSTSEC-2026-0384** (Tokio 1.54.0 interval use-after-free race) and **RUSTSEC-2026-0385** (ctutils constant-time defects). Updated to **Tokio 1.54.1 / ctutils 0.4.5**, unified direct SHA-2 on 0.11.1, rebuilt/retested all features and the runtime. No advisory ignores or relevance excuses.
- `cargo deny` 0.20.2: advisories/licenses/bans/sources PASS. Remaining legitimate transitive multiple-version warnings are visible, not suppressed. Node test dependencies separately audited: **0 findings**; install scripts disabled. Deprecated upstream memory-adapter warnings remain visible; Node is not shipped.
- Gitleaks 8.30.1: **0 source-candidate and committed-history findings**. Generated keys/passphrases stay in disposable locations/RAM. Review fingerprints use explicit public `path`/`sha256` fields (earlier path-keyed hashes caused documented generic-key false positives, not an allowlist).
- Trivy 0.76.1: **0 unresolved runtime findings at all reported severities including UNKNOWN**, no exclusions. DB updated **2026-10-23 07:12:39 UTC**. Inventory: `ca-certificates-bundle 20260909-r3`, `tzdata 2026e-r0`, `wolfi-baselayout 20230201-r30`.
- Exact rebuilt/scanned local OCI image: `sha256:d1fd7a0573c659622d8e85e7c82c0d374248b96efc670f07ce128259024bc587`; saved-image configuration identity: `sha256:1e6f07ce9988c8bd25d83cb545a2226fff223f1f3d184e271ca3cda1e14e209a`. Layer identities match. These are different OCI identity levels, not conflicting binary versions.
- Digest-pinned Chainguard static distroless remains the base. Earlier Debian Distroless CA/tzdata advisories were fixed by choosing an updated clean base, not severity filtering. Only the static Rust executable is added.

Historical reports: ignored `.work/security/` (older CI runs uploaded raw reports; the current Rust workflow publishes public count/status summaries only, with durable private raw-evidence archival still pending). Trivy does not reconstruct Rust dependencies from this ELF; Cargo audit/deny cover the locked Rust graph, and the runtime was explicitly rebuilt from that lockfile before image/client/deployment validation. Builder/test/reference/kind images are outside the final runtime scan. These checks establish no known unresolved findings within their scope, not vulnerability freedom.

## Benchmark reproduction

Run `scripts/benchmark.sh` for the internal persistence-core workload or `cargo xtask test-livesync --benchmark` for the real-client HTTP workload, using disposable data only. Keep machine profiles and raw measurements in ignored local reports. Record workload, samples, operating conditions, latency percentiles and peak RSS for your own capacity planning; do not present core metadata throughput as LiveSync wire throughput or three attachment samples as robust tail statistics.

## Remaining acceptance limits

1. Full Obsidian desktop/mobile GUI/onboarding and every optional LiveSync feature/setting were NOT run. Real Commonlib/PouchDB/fast-fetch/bootstrap fixtures are substantial protocol evidence, not GUI certification. General CouchDB admin/Mango/JavaScript/native attachment/purge features are deliberately unsupported.
2. Native GCS/Azure accounts, direct AWS/MinIO and cloud deployments/recovery drills were NOT accessed. Native provider tests remain ignored pending authorized disposable credentials; RustFS proves one real S3-compatible implementation and startup probes verify configured write guarantees.
3. Native cloud staging needs provider lifecycle/abandoned-upload cleanup; hard remote staging quota enforcement is absent. Provider durability is trusted. No workload-identity refresh or S3 session tokens; restart for provider-secret rotation.
4. No final-history GC/reclamation or finite retention; archived/orphaned bytes remain charged. Tree/leaf/ancestry/checkpoint/current-generation sequence/archive/job quotas eventually require reviewed archival/repair tooling. No public archive restore/purge API; do not edit internal rows/files.
5. Exactly one authoritative local metadata writer; no distributed lease, NFS or multi-host guarantee. Same-state lock is tested, but partitioned-node fencing/force-detach is operational. Local administration requires stopping the service.
6. Default kind CNI does not prove NetworkPolicy isolation. Private TLS/proxy behavior, tailnet ACLs, unapproved-peer isolation and policy-aware production CNI require separate validation for each deployment. Kubernetes smoke proves manifests/probes/lock and PVC-backed restart, not authenticated vault convergence or CSI disaster recovery.
7. SQLite/filesystem restoration and actual client process/container restart passed. Hardware power cuts, disk faults, amd64 execution, sustained soak, production TLS/cloud performance and operational PVC/provider disaster recovery remain untested. No broad production-readiness claim.
