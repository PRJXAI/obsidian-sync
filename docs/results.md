# LiveSync implementation evidence — 2026-10-23

## Acceptance scope

**LiveSync server phase implemented and verified with actual pinned upstream clients.** Target: Self-hosted LiveSync 1.0.39 (source pin in [protocol contract](livesync-protocol.md)), Commonlib 0.1.44 and PouchDB 9.0.0. This is a Rust CouchDB-compatible subset, not Apache CouchDB or a replacement client/UI. MCP remains deferred. GUI/mobile certification and separately authorized production/provider gates below are NOT implied. No real vault, cloud account or existing infrastructure was modified; no image was published.

Implemented: persistent revision DAG/conflicts/tombstones/history, ancestry-aware latest reads, bulk replication, bounded incremental/long-poll/NDJSON feeds, local checkpoints, opaque epoch-bound cursors, scoped bootstrap archive/reset/recreate, shared revocable Basic/Bearer credentials and per-vault grants; immutable verified bodies behind filesystem/S3/native GCS/Azure; bounded HTTP/JSON/CPU/I/O execution, quotas and jobs; schema-v3 migration/backup/recovery, static distroless/nonroot runtime and private deployments. Legacy internal CAS remains separate from wire revision trees.

## Executed gates

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

These are process/cancellation/interruption tests, not physical power-loss, kernel/disk fault-injection, multi-host writer or production CNI certification. CI commands were exercised locally; no remote GitHub Actions execution is claimed.

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

## Reproducible benchmarks

Native arm64 **Apple M4 Pro, 14 cores, 24 GiB RAM, Darwin 25.6.0/APFS**, release builds, filesystem backend, FULL/WAL, bounded pools. Repository builds/smokes completed before measurements; other OS load/caches are uncontrolled. No controlled before/after speedup is claimed.

### Actual Commonlib HTTP workload

`python3 scripts/test-livesync.py --benchmark` provisions a disposable server and generated device keys. Includes real chunking/client operations and loopback HTTP; no Tailscale/TLS, GUI or cloud latency. Eight independently authenticated writers, normal upstream change watchers; limits stay enabled (documented fixture burst 1,024). Feed phase uses a fresh reader identity and unmeasured three-second budget refill to avoid measuring a depleted token bucket. Binary content is unique random bytes, read/compared through fresh clients, not a warm chunk cache.

| Workload | Samples | Throughput | p50 / p95 / p99 |
|---|---:|---:|---:|
| ~1 KiB logical note, actual chunk + metadata durable HTTP writes | 50 | 33.39 notes/s | 29.166 / 37.699 / 45.227 ms |
| 3 MiB unique binary, actual chunked durable upload | 5 | 7.60 logical MiB/s | 390.812 / 432.111 / 432.111 ms |
| 3 MiB fresh-client read/reconstruction | 5 | 129.28 logical MiB/s | 23.567 / 27.590 / 27.590 ms |
| 8 concurrent writers, 25 ~1 KiB notes each | 200 | 38.32 notes/s | 194.653 / 269.550 / 335.347 ms |
| Full change poll, 665 current documents, requested pages of 100 | 20 | 33.35 complete polls/s | 27.884 / 33.612 / 61.349 ms |

Sampled peak server RSS: **42,303,488 bytes (40.34 MiB)** from 112 `ps` samples (~10 Hz), NOT an exact kernel high-water mark; excludes the Node client/provider. Wire transfer exceeds logical bytes due to base64/JSON. Attachment tail percentiles are the five-sample maximum, not robust production estimates. Eight-writer latency includes real writes and watcher fan-out, not merely cached metadata operations.

### Separate persistence-core microbenchmark

`scripts/benchmark.sh`: four Tokio workers and four DB/blocking slots. These are legacy INTERNAL core operations, not wire/client performance.

| Workload | Samples | Throughput | p50 / p95 / p99 |
|---|---:|---:|---:|
| 1 KiB reserve/upload/verification/durable CAS | 200 | 81.43 commits/s | 12.208 / 13.806 / 14.035 ms |
| 64 MiB streamed body/verification/read-back/publication | 3 | 693.31 MiB/s | 92.886 / 96.904 / 96.904 ms |
| Full 203-event feed, pages of 100 | 100 | 14,674 complete polls/s | 0.068 / 0.072 / 0.100 ms |
| 8 concurrent metadata-only CAS writers, existing blob | 800 | 8,054 commits/s | 0.341 / 0.425 / 0.670 ms |

Exact process peak RSS from `/usr/bin/time -l`: **11,681,792 bytes (11.14 MiB)**. Three attachment samples imply sampled-maximum tails only. Core metadata throughput must not be presented as actual LiveSync throughput. Durable per-chunk file/directory sync and FULL metadata commits remain meaningful small-write costs; no durability check was removed for speed.

## Remaining acceptance limits

1. Full Obsidian desktop/mobile GUI/onboarding and every optional LiveSync feature/setting were NOT run. Real Commonlib/PouchDB/fast-fetch/bootstrap fixtures are substantial protocol evidence, not GUI certification. General CouchDB admin/Mango/JavaScript/native attachment/purge features are deliberately unsupported.
2. Native GCS/Azure accounts, direct AWS/MinIO and cloud deployments/recovery drills were NOT accessed. Native provider tests remain ignored pending authorized disposable credentials; RustFS proves one real S3-compatible implementation and startup probes verify configured write guarantees.
3. Native cloud staging needs provider lifecycle/abandoned-upload cleanup; hard remote staging quota enforcement is absent. Provider durability is trusted. No workload-identity refresh or S3 session tokens; restart for provider-secret rotation.
4. No final-history GC/reclamation or finite retention; archived/orphaned bytes remain charged. Tree/leaf/ancestry/checkpoint/current-generation sequence/archive/job quotas eventually require reviewed archival/repair tooling. No public archive restore/purge API; do not edit internal rows/files.
5. Exactly one authoritative local metadata writer; no distributed lease, NFS or multi-host guarantee. Same-state lock is tested, but partitioned-node fencing/force-detach is operational. Local administration requires stopping the service.
6. Default kind CNI does not prove NetworkPolicy isolation. Private Tailscale TLS/ACLs and policy-aware production CNI were NOT exercised or enabled. Kubernetes smoke proves manifests/probes/lock and PVC-backed restart, not authenticated vault convergence or CSI disaster recovery.
7. SQLite/filesystem restoration and actual client process/container restart passed. Hardware power cuts, disk faults, amd64 execution, sustained soak, production TLS/cloud performance and operational PVC/provider disaster recovery remain untested. No broad production-readiness claim.
