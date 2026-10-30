# Architecture context

Start with [llms.txt](../llms.txt), [operations](operations.md) and the [protocol contract](livesync-protocol.md). User setup requests follow [the LLM setup contract](setup-with-ai.md), [getting started](getting-started.md) and [configuration](configuration.md): inspect/plan/approve first, never overwrite an existing installation, and keep key issuance out of tool stdout/model context. Native or container execution is a choice; Compose/Kustomize are optional deployment examples, not prerequisites. This is a private Self-hosted LiveSync/CouchDB replication subset, not Apache CouchDB or a new file-sync protocol. MCP is deferred.

## Components

- `src/transport.rs`: bounded operational/HTTP transport and admission; health endpoints disclose availability only.
- `src/couch/`: persistent revision DAG, aliases/generations, losing branches/tombstones, local checkpoints, changes and bulk replication. Preserve the pinned upstream Commonlib/PouchDB contract.
- `src/auth.rs`: random device principals/keys, digests, revocable vault grants and scoped reset capability. Basic username must equal principal UUID; Bearer shares the verifier. Client E2EE material never becomes a server authentication key.
- `src/db.rs`: SQLite FULL/WAL, bounded connection/blocking work and process-lifetime writer authority. Retain the process lock through canceled blocking tasks.
- `src/storage/`: common bounded streaming BlobStorage, generated vault/object keys, size/hash verification and durable create-only publication. Filesystem always available; optional S3/GCS/Azure features remain independently buildable.
- `src/sync.rs`: historical internal CAS core, **not** LiveSync revision semantics. Do not use it as a single-head replacement for offline conflicts.
- `src/jobs.rs`: persistent fenced read-only integrity jobs, bounded retries/backoff/fairness and restart recovery.
- `xtask/`: all first-party infrastructure/security/SBOM/docs/release automation. `risk.rs` and `accepted-risks.json` classify the owner's exact current-stack snapshot after report validation; they do not suppress raw findings or waive missing evidence.

## Non-negotiable behavior

Revision/body publication is durable before references; imported duplicate revisions preserve the first body even with fresh E2EE ciphertext. Contradictory ancestry fails. Preserve losing leaves, deterministic winners, branch tombstones, independent checkpoint CAS and generation-bound cursors.

Reset archives rather than deletes, inherits charged allocation, retires old grants, changes the vault UUID/epoch and is capped at 16 generations. Ordinary device keys cannot reset. No final blob/revision/tombstone/replay GC, physical purge or manual internal edits. One writer/local POSIX metadata authority; no NFS/HPA/multi-host or unfenced failover.

Bound bytes **and** structural/aggregate JSON working sets, CPU/blocking/storage tasks, admission/feeds/connections/jobs and deadlines. Authenticate before charging authenticated budgets. Waiting feeds release execution slots. No first-party unsafe Rust or unbounded spawned work.

No note paths/bodies, keys, passphrases, signed URLs or raw provider errors in logs. `issue` prints its secret once only to protected operator stdout; disable its container log driver. Remote credentials require private HTTPS and exact CORS. Config/secrets/data are mounts; final runtime adds only static `/server` to distroless/nonroot.

## Verification and delivery

Use `scripts/check.sh`, all eight feature cells, genuine `cargo xtask test-livesync`, `scripts/test-s3.sh`, Linux Docker `tests` target, image verification and disposable Compose/Kubernetes smokes. `tests/couch.rs` exercises the real router; it is not an independent Apache CouchDB oracle. GUI/mobile and real cloud/CNI/DR checks remain separate.

Live Kubernetes tests and their k3d/K3s/pause dependencies are retired by owner request. Kustomize examples remain locally rendered, without kubectl, kubeconfig, server validation or cluster certification. Never create a test cluster or use/probe the operator context or real data/accounts.

CI reuses exact image archives and source/runtime/builder native JSON/SPDX/CycloneDX with bound materials and complete Cargo/npm lock graphs. Syft catalogs; Grype matches offline after separate fresh DB retrieval. Owner decision 2026-10-30 permits only exact accepted-risk snapshot matches, including known fixable findings. All severities/suppressions stay visible. New matches, runtime/source findings, missing inventories, malformed/stale/substituted data and scan/cleanup failures still block. An empty active catalog still fails; retired pause/K3s/k3d findings remain historical, outside the active seven-image release graph.

The active Syft/Grype pins now use the published DevSecOps source-13edb52 manifest digests. Public package access is required: no consumer read token/login or private export workaround remains. The repository and both scanner packages are now verified public; anonymous index/native-config/catalog/provenance checks pass, as do both seven-image registry scans. Future package names still need owner Public settings and verification; do not restore consumer credentials. Producer delivery artifacts require a post-provenance public-access gate. Application write login remains after fresh analysis. Only actual successful producer publish/provenance/access-verified digests may replace consumer tool pins. Keep host cargo-deny until complete equivalence exists; CLI images are not compilers/daemons/services. Publication does not authorize real deployment or regulated data. See [releases](releases.md), [security](security.md), [scanner contract](scanner-pipeline.md) and [verification](results.md).

All first-party code/tests/automation use Rust; Node/npm are confined to locked upstream compatibility clients, installed without lifecycle scripts. Shell files are thin launchers. Preserve Cargo.lock and pin external actions/images/toolchains.

Follow the documentation/security-release skills. Update durable runbooks from implementation/tests, regenerate copies/source map with `cargo xtask sync-generated`, review affected source/docs, then acknowledge fingerprints. Ignore operator overrides and local scheduler state; never read/modify them as part of documentation generation.
