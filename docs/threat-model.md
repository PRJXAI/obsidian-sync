# Threat model

## Trust boundaries

Devices/agents, HTTP clients and their input are untrusted. Vault authorization is independent of transport reachability. Tailscale limits network access but does not replace per-operation authorization. A compromised device credential grants only that principal's vault/read-write permissions, until local revocation. Core random tokens are not an assertion about the unknown plugin's authentication mechanism.

The service OS identity, private metadata/blob directories, server-controlled configuration, credential files, local administrators and storage provider are trusted. Parent directories must not be writable by untrusted OS identities. An attacker with the service UID/root, arbitrary access to SQLite, or object-store write credentials can corrupt data; this design does not protect against a malicious storage provider, kernel, hypervisor, physical disk failure, or stolen backups. Use provider versioning and independent encrypted backups.

## Threats and controls

| Threat | Control and residual risk |
|---|---|
| Unauthorized vault access | Grants checked inside transactions for mutations, reservations, replay, feeds, reads, jobs; cross-vault negative tests. No HTTP data routes exist yet. |
| Compromised device/agent | Separate revocable 256-bit random core credentials; SHA-256 digests only; read-only grant support. Administrators currently need downtime for CLI access due to single-writer lock. Plugin auth integration is blocked. |
| Traversal, symlinks, rename races | Logical path validation; blob keys are typed UUIDs, unrelated to note paths. No-follow descriptor-relative walks and atomic hard-link no-clobber publication. Exclusive OS directories required. |
| Storage/SSRF misuse | Endpoints from trusted config only, S3 redirects/proxies disabled, HTTPS required except literal loopback tests. Cloud builders use administrator-controlled secrets. Least-privilege bucket/prefix policy; no client-selected URLs or presigned URLs exposed. |
| Lost/conflicting writes | SQLite FULL durability, WAL, immediate CAS transactions, immutable verified content, tombstones and scoped payload-bound replay. File/dir fsync; provider create-only probes. |
| Exhaustion | Maximum 1 GiB configured blob cap, exact size/hash, per-vault charged allocations (minimum 4 KiB/object), 100,000 revisions/vault, 1,000 events/page, 128-byte replay keys, bounded uploads/worker/connection pools. HTTP probes: 64 simultaneous connections, 15-second connection lifetime, no body-consuming routes. Per-device request/batch rate limits must be designed with the missing adapter; no data API is exposed. |
| Remote staging exhaustion | Native GCS/Azure use staging + conditional copy; configure provider lifecycle/abandoned-upload cleanup and budget temporary overhead. Provider staging hard-quota enforcement is not implemented; these adapters are not production-validated. No final-object GC. |
| Job race/stale owner | Durable atomic claims; unique attempt tokens fence completion; process lock fences restart recovery. One bounded worker, whole-job timeout, jittered finite retry, per-vault round-robin. Jobs only read immutable blobs. |
| Credential/content leaks | Fixed structured events, no raw error sources, URI tracing, CORS, remote admin routes, or note logging. CLI `issue` deliberately prints its new secret once; protect stdout. Disable shell tracing around secrets. |
| Supply-chain compromise | Pinned stable toolchain/lockfile, minimal features, RustSec/deny, digest-pinned Distroless image, image and secret scans, CI action pins. Scanners do not prove absence of vulnerabilities. Review updates before merging. |

## Deployment policy

No public ingress, host-network pod, privileged container, default credential, Funnel or HPA. Run non-root, read-only rootfs, no added capabilities, bounded memory/processes, private mounted storage. Compose binds loopback; use private Tailscale Serve HTTPS, tailnet ACLs and device approval. Kubernetes ClusterIP/NetworkPolicy is internal only. The sample cloud egress policy allows TCP/443 broadly; narrow to your provider/egress gateway. The disposable kind smoke cluster does not itself prove NetworkPolicy enforcement (kind's default CNI does not enforce it).

The only HTTP surface currently is liveness and deliberately failing readiness. CORS is absent. TLS is terminated by a private Tailscale Serve proxy, not this health-only listener. Do not transmit future bearer credentials remotely over plaintext; implement adapter-specific TLS/CORS/rate/body/batch limits before enabling readiness.
