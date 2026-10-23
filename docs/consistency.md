# Consistency contract (protocol-independent core)

Historical/internal-core contract: these operations describe `src/sync.rs`, not LiveSync's wire semantics. The owner selected **Self-hosted LiveSync**; its authoritative revision-tree, encrypted replay, checkpoint and reset contract is in [livesync-protocol.md](livesync-protocol.md). Never translate offline CouchDB branches into this legacy single-head model.

## Authority and isolation

One process owns the metadata directory, enforced by an OS advisory file lock held for its lifetime, not a Kubernetes replica count. SQLite on local POSIX storage is authoritative (WAL, synchronous=FULL, foreign keys, immediate write transactions). Never use NFS or separate metadata copies pointing at the same blob namespace. Each installation requires an exclusive S3 prefix. A shared local lock does NOT coordinate different hosts; cross-host multi-writer deployments are unsupported.

All logical operations require an authenticated, revocable principal and an explicit vault grant. Principals are independent of vault IDs. Credentials are random 256-bit bearer secrets stored only as SHA-256 digests (not human passwords); the LiveSync adapter verifies these keys as Basic UUID/password credentials (or Bearer tokens) through the same identity/grant layer. Optional per-database bootstrap reset permission is separate from ordinary write permission. Administrative operations are local CLI operations requiring access to metadata, never HTTP routes. Health probes disclose no vault data.

## Publication and races

1. Allocate an upload reservation in an immediate transaction, authorize, and charge the vault quota BEFORE uploading. Bind its immutable random object key to that vault. Each reservation charges max(content size, 4 KiB), bounding zero-byte allocations. Reservations are never automatically released: interrupted uploads consume quota until a future supported repair tool can verify and repair them. This intentionally favors integrity over availability.
2. Stream content to an immutable object; enforce exact size, configured maximum, and SHA-256. Filesystem publication uses no-follow descriptor-relative access, private staging, fsync(file), atomic hard-link publication with no overwrite, and fsync(directory) after publication and staging unlink. Duplicate filesystem uploads re-sync the existing final file and directory before returning a recoverable conflict: mere visibility/read-back is not a durability proof after an interrupted fsync. A busy incomplete stage fails closed. S3 uses conditional PUT (`If-None-Match: *`), fixed content length and a provider capability probe. Existing objects are never overwritten. HTTP success is necessary but S3 durability remains the provider's responsibility.
3. Record the durable object and digest in SQLite. A failure between object publication and metadata commit leaves a charged, unreferenced reservation. No automatic blob GC runs, so neither active uploads nor historical content can be collected.
4. Publish a document reference in an immediate transaction: authorize again, compare expected revision, insert the next globally ordered vault revision, update the head, store the idempotency result atomically. Concurrent callers cannot both win a CAS. Deletion is a tombstone. Rename atomically checks both source and destination revisions and publishes both changes. Tombstoned destinations cannot be overwritten without their expected revision.

Retries use a caller-provided idempotency key scoped to principal, vault and operation. The canonical serialized request is hashed, including the object key/digest. Same key and payload returns the recorded result; different payload is rejected. Ambiguous commit results must be retried with the SAME key. Revocation is checked even on replay.

## Retention and recovery

Revisions, change events, tombstones, idempotency results, reservations and blobs are retained indefinitely in this version. Cursors are monotonically increasing vault revision numbers, with a bounded page size and explicit high-water mark. Future cursors fail; no expired cursors exist under this policy. Quotas include historical and orphaned allocations. A fixed 100,000-revision/vault limit bounds change/head/replay metadata; exhausted vaults fail mutations without removing history. Job quotas include terminal records. These conservative limits need protocol-aware archival/admin tooling before sustained production use. Space reclamation and finite retention require a later protocol-aware design; do not delete backend files manually.

SQLite recovery replays WAL; startup recovers jobs previously running under the exclusive process lock. Job claim tokens fence completion: an old attempt cannot complete a newer claim. Integrity jobs are read-only, at-least-once, bounded, quota-limited, round-robin across vaults, with finite retry and exponential jitter. Worker shutdown stops claiming, cancels bounded read work and leaves recoverable persisted ownership. No exactly-once external effects are claimed.

## Interruption matrix

- Before reservation commit: no accepted upload or quota charge.
- After reservation, before/during blob upload: charged reservation; deterministic per-object local staging may remain, never visible as a committed note. Restart under the exclusive writer lock removes incomplete staging using no-follow dirfds. Until restart, the same interrupted filesystem upload may fail closed. Anonymous S3 local spools are removed on close/process exit.
- After blob durability, before blob metadata: orphan stays charged; no automatic deletion.
- After blob metadata, before head transaction: durable unreferenced content; safely reusable.
- During head transaction: all reference/revision/idempotency changes commit together or none do.
- After commit, before response: retry retrieves the same result.
- During integrity job: startup requeues; claim tokens reject stale completion.

Backups must capture SQLite consistently plus all immutable blobs (including staging/reservations for accounting). See operations.md. The service now runs the tested LiveSync-compatible adapter; readiness is available after initialization and unavailable during shutdown. Keep the distinction between the wire DAG and the internal CAS model explicit.
