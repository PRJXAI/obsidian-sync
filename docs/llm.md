# LLM context: read this before changing the repository

## Current product boundary

This began as an EMPTY repository. The requested Obsidian plugin was not named and no protocol sources existed. The owner has been asked for authoritative sources. **There is no implemented client sync wire protocol, authentication adapter, or compatibility evidence.** `/health/live` returns 204; `/health/ready` deliberately returns 503. Do not turn this core into an invented REST/CouchDB server and claim compatibility. No UI/plugin/mobile app is in scope.

## Implemented architecture

One stable-Rust binary, Tokio, Axum operational probes, SQLite FULL/WAL metadata, a bounded blocking/connection pool, persistent process-lifetime writer lock, core principal grants, reservation-first immutable uploads, transactional CAS/replay/rename/tombstones/change pages, and a single persisted integrity worker. The internal logical model is provisional until the real plugin contract is understood. Credentials/revisions/cursor semantics may need adapter-driven changes.

`BlobStorage` is object-safe and provider-independent. `Store` wraps a shared trait object. Adapters: hardened filesystem, S3-compatible (including MinIO interface), native GCS, native Azure. All compile by default; filesystem always enabled, optional features `s3`, `gcs`, `azure`. Same storage contract is used for all; native cloud end-to-end validation requires disposable credentials. S3 is not the client-facing protocol.

## Invariants

- Read [consistency.md](consistency.md) BEFORE changing mutations, jobs or storage publication.
- Content is durable and verified before references commit. Metadata/revision/CAS/replay happen atomically in SQLite, not an in-memory lock. Concurrent writes never silently win over a competing revision.
- Authorize every core operation against a live principal + vault grant, including idempotency replay, changes, blobs and job status. Secrets/content/signed URLs are never logged. Local admin access is trusted and offline.
- Backend roots and parents are service-controlled. UUID dirfd/no-follow operations enforce confinement and no-clobber hard-link publication. Never allow agents to edit backend files.
- The writer lock MUST outlive canceled blocking tasks; DB work captures it explicitly. Separate metadata copies over one bucket/root are NOT coordinated. No NFS/multi-writer/HPA/lease claims.
- No automatic final-blob GC or history expiry. Reservations charge max(size, 4 KiB); 100,000 revisions/vault bounds metadata. Quotas/terminal job records can eventually require future supported archival tooling. Do not "fix" exhaustion by deleting SQLite rows.
- Jobs are read-only, at-least-once, token-fenced, quota-limited and round-robin. Startup recovers process-owned jobs only after writer lock acquisition. No exactly-once claim.
- Native cloud adapters use staging plus conditional copy; provider staging lifecycle and actual-provider tests remain acceptance requirements. Azure uses expiring HTTPS-only container-scoped SAS, not account keys; workload identity refresh is not implemented.
- Runtime image is Distroless static/nonroot, application binary only; no shell/config/secrets copied. Compose binds loopback. Kubernetes is internal-only with Recreate, PVC, restrictive contexts and NetworkPolicy. Readiness is intentionally false.

## Navigation and evidence

- [Generated source map](source-map.md)
- [Storage contract/adapters](storage.md)
- [Threat model](threat-model.md)
- [Build/run/backup/recovery](operations.md)
- [Actual results and blockers](results.md)
- `.agents/skills/maintain-docs/SKILL.md`: safe create/update/delete and source-drift review.
- `.agents/skills/security-release/SKILL.md`: acceptance workflow.

Run `scripts/check.sh`, `scripts/check-features.sh`, `scripts/test-s3.sh`, `scripts/validate-deployments.sh`, image build + `scripts/scan-security.sh`, then disposable smoke scripts. Never touch the operator's current kubecontext: `scripts/smoke-kubernetes.sh` owns its temporary cluster/kubeconfig. No real infrastructure, images published, or existing vaults modified. Fresh scanners plus passing tests mean no known unresolved findings in the performed checks, never "vulnerability-free".
