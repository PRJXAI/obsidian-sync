# Repository instructions

Read README.md, docs/llm.md, docs/consistency.md and docs/threat-model.md before changing code.

## Non-negotiable constraints

- Target is Self-hosted LiveSync (vrtmrz/obsidian-livesync), pinned source and contract in docs/livesync-protocol.md. Preserve PouchDB/CouchDB revision trees, conflicts, tombstones and checkpoints; do not map them to the old single-head CAS model. Implement verified upstream-client tests before claiming compatibility. MCP remains deferred.
- Priorities: isolation/security, integrity/race protection, reliable async work, performance/simplicity.
- No first-party unsafe Rust. No note content, bearer tokens, secret keys, signed URLs or raw provider errors in logs.
- BlobStorage is the common streaming interface. All adapters must preserve create-only publication, vault-scoped server-generated keys, bounded memory and hash/size verification. Never use canonicalization as the only filesystem boundary.
- SQLite transactions implement CAS and replay. Never replace persistent checks with a mutex. Preserve the process lock through canceled blocking work. No multi-writer deployments, NFS, HPA, public ingress, or Tailscale Funnel.
- No GC of final blobs/revisions/tombstones/replay records. Design and test a protocol-aware retention policy before adding deletion. Do not edit internal storage by hand.
- Keep the runtime image Distroless static/nonroot with only the Rust executable added; configuration/secrets/data are mounts, not image layers.
- Never touch real vaults, clusters, buckets, or publish images without explicit permission. Kubernetes tests MUST use scripts/smoke-kubernetes.sh and its disposable kubeconfig, never the current context.

## Workflow

1. Write down changed consistency/security guarantees before implementing concurrent mutations.
2. Add negative authorization, race, cancellation and restart tests, not just happy paths.
3. Use bounded blocking pools for SQLite/fs sync work, streaming I/O for attachments. Do not spawn unbounded tasks.
4. Run scripts/check.sh, scripts/check-features.sh, scripts/test-s3.sh, scripts/validate-deployments.sh; then image scan and disposable deployment smoke tests. Record exact results and blocked checks in docs/results.md.
5. Run cargo audit and cargo deny check with fresh advisory data. Never ignore advisories merely to make CI green. Dependency license approvals in deny.toml are policy, not advisory exceptions.
6. Follow .agents/skills/maintain-docs/SKILL.md. Update authored docs with behavior changes; regenerate copies/source map with scripts/sync-generated.py. Review source drift via scripts/docs.py check; acknowledge only after reading affected docs.
7. Commit Cargo.lock. Keep toolchain, Docker builder and CI toolchain in sync; pin external images/actions by digest/commit.

## Ownership map

- src/transport.rs: operational probes and bounded Self-hosted LiveSync/CouchDB-compatible transport.
- src/couch/: LiveSync-compatible revision trees, persistent checkpoints and HTTP contract.
- src/auth.rs: revocable core principals/vault grants; adapter authentication must honor actual plugin contract.
- src/sync.rs: upload reservations, CAS mutations, scoped replay, cursor pages.
- src/db.rs: SQLite schema, bounded connection pool, process authority, backup.
- src/storage/: common trait and filesystem/S3/GCS/Azure adapters (MinIO uses S3).
- src/jobs.rs: persisted read-only integrity jobs, claim fencing, retries and fairness.
- config/: canonical deployment configs; Kustomize copies are generated.
- docs/results.md: measured evidence, not aspirational claims.
