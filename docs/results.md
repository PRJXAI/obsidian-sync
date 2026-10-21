# Implementation evidence — 2026-10-21

## Acceptance status

**Infrastructure/core implemented and exercised; overall product acceptance BLOCKED.** No Obsidian plugin or authoritative protocol was supplied. There is no sync wire API, no actual plugin compatibility test, and readiness intentionally remains 503. No real vault/infrastructure was modified and no image was published.

Implemented: common streaming storage interface with filesystem, S3-compatible/MinIO interface, native GCS and Azure adapters; immutable verified publication; SQLite FULL/WAL metadata and bounded connection/blocking pools; transactional CAS, atomic rename, tombstones, paged change log and scoped payload-bound replay; revocable core principals/grants; persisted quota-limited/fair integrity jobs with fenced claims/retry/crash recovery; offline admin/backup commands; Distroless binary-only application image, private Compose/Kustomize deployments; CI, repository skills, documentation lifecycle tools and LLM context.

## Executed correctness/build checks

| Check | Actual outcome |
|---|---|
| `cargo build --locked` | PASS |
| `cargo build --release --locked` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --locked` | PASS: 21 active tests; 3 provider tests explicitly ignored in default run |
| All 8 feature subsets | PASS: debug AND release builds, all-target Clippy, tests; filesystem always enabled |
| Real local S3-compatible contract | PASS: separately executed ignored S3 test against disposable RustFS, including conditional create races and 8 MiB content |
| Linux/musl Docker test target | PASS: release/debug builds, formatting, all-target Clippy, 21 active tests (3 provider tests ignored) on Linux arm64 |
| Python maintenance tests | PASS: 3 tests for create/update/drift/review/deletion/link/traversal/symlink safeguards |
| Generated configs/source map and doc drift | Checked by maintenance commands; source fingerprints recorded after review |
| Docker runtime build/verification | PASS: static 64-bit ELF with no interpreter, explicit UID/GID 65532, only `/server` executable; no shell/package manager |
| Compose configurations | PASS: filesystem, S3 override, disposable test service render |
| Kustomize base + filesystem/S3/GCS/Azure overlays | PASS: render; overlays also Kubernetes API server dry-run in disposable kind |
| Compose smoke | PASS: loopback probes (204/503), second-writer exclusion, graceful stop and persistent restart |
| Disposable Kubernetes smoke | PASS: v1.36.1 kind, PVC-backed startup/restart, probes, runtime lock exclusion; separate disposable kubeconfig |

Tests include cross-vault/readonly/revoked access on mutations, feeds, blobs, reservations/uploads and jobs; malformed inputs/paths/endpoint settings; quota/revision budgets; concurrent same-note CAS, update/delete and rename/update; payload-changing replay rejection; immutable storage publication races; static and actively swapped symlink escapes; canceled blocking work retaining authority; interrupted blob publication; canceled staging/restart recovery; stale job completion fencing; claim races, quota/fairness/backoff; worker shutdown; and actual SQLite backup/restore with feed/blob verification. Two property tests exercise path invariants (default Proptest case counts).

These are process/cancellation/interruption tests, **not physical power-loss, kernel fault-injection, distributed multi-writer, or production CNI isolation tests**. The CI workflow is provided; its commands were exercised locally, but no remote GitHub Actions run is claimed.

## Security scans

- `cargo audit` **PASS**, cargo-audit 0.22.1: 0 known unresolved advisories/warnings. RustSec database: 1,348 advisories, commit `4b587f00996ebe5c05a73eaef105ef241e876414`, updated **2026-10-21 06:20:38 UTC**.
- `cargo deny check` **PASS**, cargo-deny 0.20.2: advisories, licenses, bans and sources pass. No advisory ignores; legitimate transitive multiple-version warnings remain visible under the documented dependency policy.
- **Gitleaks 8.30.1**: 0 findings in source-control-eligible working-tree files AND the full committed Git history. Generated credentials stay in disposable locations and are removed. Git history scanning runs whenever HEAD exists and in CI with full checkout history. Initial path-keyed review checksums triggered four generic-key false positives; recomputation confirmed they were public source SHA-256 hashes. The manifest now retains the full hashes in explicit `path`/`sha256` entries, with no scanner ignore/allowlist.
- **Trivy 0.76.1 runtime scan PASS**, 0 known unresolved findings across all reported severities (including UNKNOWN), no advisory exclusions. Advisory DB updated **2026-10-21 07:13:45 UTC**. Runtime inventory: `ca-certificates-bundle 20260909-r3`, `tzdata 2026e-r0`, `wolfi-baselayout 20230201-r30`.
- Initial Google Debian Distroless images failed: Debian 13 `DSA-6572-1` in `ca-certificates`, Debian 12 also had CA/tzdata findings. Remediation: switch to current digest-pinned **Chainguard static distroless**, not a severity filter or advisory suppression. Application layer still adds only the Rust binary.
- Final local runtime OCI identity: `sha256:095d3b737209daa55878d49bc4e4ae2307f0790470450b3126582df5ecd9351f`. Trivy's saved-image configuration identity is `sha256:1b3ea633d767245e3b8aeb055a184883c7d96a10fcfe60c2585cfbf498b77891`; these use different OCI identity levels. Scanned layer digests match the inspected runtime image.

Reports are generated under ignored `.work/security/`; CI uploads them. Trivy reports no Rust language manifest in the static binary: Rust dependency coverage comes from Cargo audit/deny, not ELF inference. Test-service, builder and kind node images are outside the final runtime scan's scope. Passing these checks means no known unresolved findings **within the checks performed**, never proof of vulnerability freedom.

## Benchmarks

Reproduce with `scripts/benchmark.sh`. Release build, native arm64 **Apple M4 Pro, 14 cores, 24 GiB RAM, Darwin 25.6.0, APFS**, four Tokio workers, four bounded DB/blocking slots, SQLite FULL/WAL, temporary filesystem backend. Measured after repository builds/smokes completed; other machine load is not controlled. These are warm local **persistence-core** results, not Linux production, network, S3/cloud, end-to-end sync, or actual plugin benchmarks.

| Workload | Samples | Throughput | p50 / p95 / p99 |
|---|---:|---:|---:|
| 1 KiB note: reserve, streamed upload, verification, durable CAS commit | 200 | 98.36 commits/s | 10.039 / 11.084 / 11.381 ms |
| 64 MiB attachment: streamed upload/read-back + metadata publication | 3 | 244.45 MiB/s (3.82 uploads/s) | 261.555 / 262.369 / 262.369 ms |
| Incremental feed: 203 events, pages of 100, complete poll | 100 | 12,639 full polls/s | 0.075 / 0.099 / 0.148 ms |
| 8 concurrent clients, independent paths, CAS metadata referencing existing blob | 800 | 7,750 commits/s | 0.342 / 0.415 / 0.689 ms |

Process peak RSS across all workloads: **11,649,024 bytes (11.11 MiB)**, measured by `/usr/bin/time -l`. Attachment samples are deliberately few: reported p95/p99 are the sampled maximum, not statistically robust production tail estimates. Client concurrency tests do not include upload/network time; conflict correctness is tested separately.

The upload path showed repeated directory synchronization cost. Publication and staging unlink now share one directory fsync, while retaining file fsync, final directory durability and explicit file+directory re-sync on duplicate/interrupted publication. Earlier exploratory runs were contended by builds, so no controlled before/after speedup is claimed. No durability check was removed to improve benchmark numbers.

## Compatibility evidence and remaining blockers

1. **Authoritative Obsidian plugin/protocol missing.** Authentication/revision/conflict/deletion/pagination/sync wire semantics, plugin connection settings, real plugin tests, per-device HTTP rate/body/batch policies and protocol-aware retention cannot be completed honestly. The core revision model is provisional, not a compatibility claim.
2. Real native GCS/Azure accounts were NOT accessed; their shared contract tests remain ignored pending disposable credentials. MinIO and AWS were NOT directly exercised; RustFS proves one real S3-compatible implementation, with per-provider startup conditional-write probes. No cloud Kubernetes/Compose deployment smoke is claimed.
3. Native GCS/Azure staging requires provider lifecycle/abandoned-upload cleanup; hard remote staging quota enforcement is not implemented. Provider durability remains trusted. Provider credential refresh/workload identity and S3 session tokens are not implemented; restart for secret rotation. Azure requires a dedicated private container and expiring HTTPS-only container SAS.
4. No finite history/tombstone/replay retention or final-blob GC. Interrupted reservations stay charged; 100,000 revisions/vault and terminal-job-inclusive quotas eventually require future supported archival/repair tooling. Do not delete internal files/rows manually.
5. Exactly one authoritative local metadata writer, no NFS or multi-host leases/fencing scheme. Same-PVC process lock is tested; force-detach/partitioned-node fencing remains an operator responsibility. CLI administration currently requires stopping the server.
6. Default kind CNI does not enforce NetworkPolicy; actual CNI network isolation and private Tailscale TLS access were not exercised. Tailscale configuration is documented, never enabled on the owner's infrastructure.
7. Backup/restore was tested at SQLite/core/filesystem level, not as an operator cloud/PVC recovery drill. Hardware power loss, disk faults, amd64 execution and sustained soak tests remain untested. Linux arm64 build/runtime correctness was exercised; Linux performance benchmarks remain outstanding.

Supply the plugin name/source next. Passing infrastructure tests must not be mistaken for a finished compatible sync product.
