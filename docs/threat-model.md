# Threat model

## Trust boundaries

Clients, documents and network requests are untrusted. Tailscale narrows exposure but does not replace authorization. The OS/kernel, service UID, private backend parents, operator configuration/credential files and storage provider are trusted. Provider write-credential compromise, malicious OS/hypervisor/provider, disk loss and stolen backups need external controls and independent encrypted recovery copies.

Self-hosted LiveSync authenticates with a principal UUID and random 256-bit key as Basic credentials; Bearer uses the same verifier. SQLite stores digests, not human passwords. Client encryption material stays client-side. A compromised authorized write device can make malicious edits within its grants; retention/backups support recovery, not prevention of every authorized action.

## Enforced controls

| Threat | Control / residual boundary |
|---|---|
| Cross-vault reads/writes | Reauthorize current grants on documents, revisions, feeds, bulk APIs and checkpoints. Negative wrong-vault/read-only/revoked/malformed-credential tests. |
| Credential leakage | Separate revocable device keys; no note paths/bodies/tokens/signed URLs/raw provider errors in logs. Offline `issue` prints once to protected stdout; disable its container log driver. |
| Reset/admin escalation | No implicit global admin, arbitrary alias creation, configuration/user/security mutation or physical purge. Separate scoped bootstrap reset, archived generations, inherited charged quota, retired old grants and a 16-generation cap. |
| Conflicts/replay/lost writes | Persistent revision DAG, deterministic winner, retained losing branches/tombstones, atomic publication/quota/sequence checks, first imported body wins and contradictory ancestry fails. Checkpoints are independent CAS records. |
| Cancellation/old writers | SQLite FULL/WAL transactions and process-lifetime authority retained through canceled blocking work. Generation-bound cursors and grant retirement fence stale reset clients. No distributed-writer or exactly-once claim. |
| Filesystem traversal/races | Client IDs are not backend paths. Server-generated vault/object keys, descriptor-relative no-follow walks, exclusive staging, fsync and create-only publication. Trusted parents remain required. |
| SSRF/provider misuse | Endpoints/prefixes/credentials are operator configuration, not document input. Remote HTTPS; S3 redirects/proxies disabled; loopback HTTP opt-in and startup conditional-create probes. Native IAM/lifecycle tests remain separate. |
| Resource exhaustion | Independent byte/structure/aggregate JSON budgets; bounded sockets/admission/feed/CPU/SQLite/fs/storage queues, rate limits and finite body/operation/drain deadlines. Authenticate before spending authenticated budgets. Not universal DoS immunity. |
| State/staging growth | Retained-allocation/quota/tree/sequence/checkpoint/job/reset limits. No final-data GC; orphaned/archived bodies remain charged. Provider staging lifecycle and hard remote quota remain operational gaps. |
| Async jobs | Persistent fenced claims/attempt tokens, recovery under exclusive authority, bounded retries/backoff/fairness and read-only immutable-body checks. Not a durable security audit trail. |
| CSRF/CORS | Exact origins; reject unapproved Origin on actual requests. Basic/Bearer still required; no cookie/JWT shortcut. |
| Prompt injection | Document instructions are data, not executable operations. No design-document JavaScript or MCP execution; future MCP needs independent scopes/approval. |
| Supply chain | Literal toolchain/lock/action/image pins, independent source/native inventories, bound archives/materials, fresh audits/scans and real-client tests. Exact owner-accepted risks stay visible; new findings and inventory/scan failures block. |

## CI and disposable infrastructure

Only public supplier/source artifacts and synthetic data enter tools. Source/history scans minimize inputs; bare mirrors exclude ignored operator files. Scanner roots/inputs are read-only with bounded resources, finite captures/deadlines, separate retrieval/offline analysis, isolated output and no Docker socket. Output validation is not DLP; a compromised tool can encode input in reports.

K3d/K3s and their Docker-access helpers are privileged **test infrastructure**, not the application runtime. Tests enter only through `scripts/smoke-kubernetes.sh`: checked Unix endpoint, private HOME/config/kubeconfig, loopback API, no default-context merging, pre-existing-resource refusal, fresh owned data and cancellation-safe checked cleanup. Persistent authenticated identity, pod/PVC replacement and writer exclusion are tested. Real contexts/data are prohibited; policy-CNI enforcement is not certified by this smoke.

Runner root/same-UID processes and the local daemon are trusted. Hashes/nofollow/private leaves are not race-free protection against those actors or an authorized malicious producer. Host archive/cache/Docker accumulation lacks a hard filesystem quota.

## Accepted and unverified risks

The owner's **2026-10-30** current-stack decision is implemented as exact artifact/package/advisory rules, not scanner filtering or proof of exploit absence. It changes vulnerability disposition, not storage/authentication/retention/runtime guarantees. No missing inventory, failed contract, scan error, production deployment or regulated-use approval is inferred. See [security and operational risk register](security.md).

Private HTTPS, restrictive tailnet access, provider IAM/immutability, destination-bound egress, protected source/release authority, durable private evidence, privacy-safe security auditing, crypto/key custody, matched encrypted backup/restore and protocol-aware retention requirements remain deployment responsibilities. Client E2EE is not server-mandatory; authorized reads intentionally export their granted vault. No FIPS/regulatory, GUI/mobile, native-provider DR or complete vulnerability-freedom claim.

## Deployment invariants

No public ingress/Funnel, HPA, multi-writer/NFS, host-network application or extra runtime executable. Compose binds loopback; Kubernetes uses ClusterIP/Recreate/PVC and restrictive security examples, not an automatic private TLS proxy. Remote credentials must not cross plaintext connections.

Liveness/readiness disclose only operational availability. Readiness is 204 after initialization and 503 during shutdown; it is not proof of convergence, integrity, backup recovery or network-policy enforcement. See [operations](operations.md), [protocol](livesync-protocol.md), [storage](storage.md) and [verification status](results.md).
