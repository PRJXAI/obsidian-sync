# LiveSync implementation evidence — 2026-10-23

## Current audit/remediation status

**Expanded supply-chain gate: FAILED / release acceptance blocked.** The subsequent [security audit](security-audit.md) fixed unauthenticated rate-budget depletion, refreshed 14 Rust dependencies and pinned build/test/tool images, and added shared CI image artifacts, runtime-to-release content verification and complete source/runtime/builder SBOM/materials generation. Runtime and populated-builder scans are clean; current official test/scanner/frontend images still have unresolved package findings. No severity/advisory exceptions were added. The implementation evidence below predates this expanded gate and is not an all-supply-chain clean claim.

Remediation verification (2026-10-23, disposable local arm64):

| Check | Actual result |
|---|---|
| `scripts/check.sh`; all eight subsets via `scripts/check-features.sh` | PASS: default **42 active Rust tests**, 3 provider tests ignored; debug/release, fmt, Clippy, fresh RustSec/deny |
| Python regression/maintenance tests | PASS: **18 tests**, including image-content substitution/stale evidence, SBOM dev-lock completeness, unpinned image rejection, scanner cancellation cleanup, LLM guide links, ignored-configuration privacy and caller-identity enforcement for both shell Trivy invocations |
| Native and final-runtime Commonlib/PouchDB; S3/RustFS contract/client fixture | PASS, including restart; no real vault/provider account |
| Reference CouchDB | PASS against updated digest-pinned **3.5.3** |
| Linux/musl Docker test target; static/nonroot image verification | PASS |
| Compose/Kustomize rendering; Compose smoke; disposable kind | PASS: **kind 0.33.0 / Kubernetes 1.37.0**, dedicated kubeconfig (inherited disposable sentinel remained byte-for-byte unchanged), PVC restart and lock exclusion; not CNI enforcement |
| Fresh runtime and populated-builder Trivy, RustSec/deny, source/history Gitleaks, npm audit | PASS within their scopes; no runtime/builder package findings or Rust/npm advisories |
| `python3 scripts/scan-supply-chain.py --platform linux/arm64` | **FAIL (exit 1)**: complete 10-image inventory, findings remain in 7 upstream image pins; exact counts/scope in [audit](security-audit.md) |
| Workflow actionlint 1.7.12 | PASS; local validation does not assert a successful remote GitHub Actions run |
| `python3 scripts/generate-sbom.py` | PASS: six SPDX/CycloneDX files, native-toolchain identity and `materials.json`; source graph includes all **287 registry Rust dependencies and 129 locked npm dependency entries**, including test dependencies |
| `python3 scripts/verify-release.py` | PASS against the exact fresh scanned runtime; negative config/layer/stale/UNKNOWN tests pass |

Exact locally rebuilt runtime OCI index: `sha256:7893527e4e4956f1c68376842855e84f66f63a7bb95fa1d774599d46acc53c64`; exported configuration: `sha256:c9cd12708a9dc6ce2d12ac14bf5acae8c8a211d41b5e160441ea74b6c07a85b6`. These image measurements came from a pre-publication remediation source snapshot, not a release certification. Regenerate release evidence against the committed source. Scanner DB: Trivy 0.76.1, updated 2026-10-23 07:12:39 UTC; RustSec 1,350 advisories at `f7b2f6bc663452200bbe639ebb75e0c762b3422b`. Raw evidence: ignored `.work/security-audit/`, `.work/security/`, `.work/sbom/`.

No speedup, wire-performance or production-rollout claim is made by this remediation. Machine-specific benchmark profiles and deployment-specific receipts are excluded from this document. Native GCS/Azure, production ACL/CNI/DR and full GUI/mobile checks remain outstanding. SBOM/materials and content verification are unsigned; trusted CI/operator delivery remains required.

## Linux scanner permissions regression

The first published workflow run on the amended source passed all eight Rust feature jobs, Linux build/tests, integration and SBOM generation, but failed security scanning with `mkdir /cache/db: permission denied`. Root with all capabilities dropped could not write runner-owned bind mounts; this was a scanner setup failure, not a successful vulnerability assessment.

Both shell Trivy invocations and the Python supply-chain scanner now use the caller's numeric UID/GID and `HOME=/tmp`. Capability dropping, no-new-privileges, socket isolation and fail-on-findings policy remain unchanged. Offline regressions validate identity/restrictions for database, runtime, builder and per-image commands. A disposable Linux-backed volume smoke reproduced the old root/cap-drop denial and verified that a simulated non-root owner could create the cache and write a Trivy version report with all capabilities still dropped. No credentials, real data or host permission changes were involved. Remote revalidation of the fix is tracked separately from these executed local checks; the upstream-image findings remain blocking.

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

Reports: ignored `.work/security/` (CI uploads them). Trivy does not reconstruct Rust dependencies from this ELF; Cargo audit/deny cover the locked Rust graph, and the runtime was explicitly rebuilt from that lockfile before image/client/deployment validation. Builder/test/reference/kind images are outside the final runtime scan. These checks establish no known unresolved findings within their scope, not vulnerability freedom.

## Benchmark reproduction

Run `scripts/benchmark.sh` for the internal persistence-core workload or `python3 scripts/test-livesync.py --benchmark` for the real-client HTTP workload, using disposable data only. Keep machine profiles and raw measurements in ignored local reports. Record workload, samples, operating conditions, latency percentiles and peak RSS for your own capacity planning; do not present core metadata throughput as LiveSync wire throughput or three attachment samples as robust tail statistics.

## Remaining acceptance limits

1. Full Obsidian desktop/mobile GUI/onboarding and every optional LiveSync feature/setting were NOT run. Real Commonlib/PouchDB/fast-fetch/bootstrap fixtures are substantial protocol evidence, not GUI certification. General CouchDB admin/Mango/JavaScript/native attachment/purge features are deliberately unsupported.
2. Native GCS/Azure accounts, direct AWS/MinIO and cloud deployments/recovery drills were NOT accessed. Native provider tests remain ignored pending authorized disposable credentials; RustFS proves one real S3-compatible implementation and startup probes verify configured write guarantees.
3. Native cloud staging needs provider lifecycle/abandoned-upload cleanup; hard remote staging quota enforcement is absent. Provider durability is trusted. No workload-identity refresh or S3 session tokens; restart for provider-secret rotation.
4. No final-history GC/reclamation or finite retention; archived/orphaned bytes remain charged. Tree/leaf/ancestry/checkpoint/current-generation sequence/archive/job quotas eventually require reviewed archival/repair tooling. No public archive restore/purge API; do not edit internal rows/files.
5. Exactly one authoritative local metadata writer; no distributed lease, NFS or multi-host guarantee. Same-state lock is tested, but partitioned-node fencing/force-detach is operational. Local administration requires stopping the service.
6. Default kind CNI does not prove NetworkPolicy isolation. Private TLS/proxy behavior, tailnet ACLs, unapproved-peer isolation and policy-aware production CNI require separate validation for each deployment. Kubernetes smoke proves manifests/probes/lock and PVC-backed restart, not authenticated vault convergence or CSI disaster recovery.
7. SQLite/filesystem restoration and actual client process/container restart passed. Hardware power cuts, disk faults, amd64 execution, sustained soak, production TLS/cloud performance and operational PVC/provider disaster recovery remain untested. No broad production-readiness claim.
