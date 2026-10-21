# Private Obsidian sync server core

Rust persistence/storage infrastructure for a future compatible self-hosted Obsidian server, private behind Tailscale or a cluster network.

> **Plugin integration is blocked.** This repository was empty and no plugin/protocol was supplied. Provide its name and authoritative source before client endpoints can be implemented. This is not currently usable by an Obsidian plugin. Readiness deliberately returns 503; no replacement protocol is exposed.

Implemented core:

- One streaming storage interface: filesystem, S3/MinIO-compatible, native GCS, native Azure.
- Verified immutable blobs, SQLite durable metadata/CAS, scoped idempotency, tombstones, atomic rename and paged changes.
- Revocable core credentials/vault grants, bounded asynchronous work, persisted integrity jobs and runtime single-writer exclusion.
- Distroless static/nonroot image with only the Rust binary added, loopback-bound Compose, internal-only Kustomize overlays.
- Tests, security/CI gates, maintenance scripts, repository skills and LLM documentation.

```sh
cargo build --locked
cargo test --workspace --locked
scripts/test-s3.sh                 # disposable real S3-compatible service
scripts/check-features.sh          # all eight feature combinations
scripts/validate-deployments.sh
```

Cloud end-to-end claims, protocol compatibility and production acceptance require additional evidence. See [actual results and limitations](docs/results.md).

## Documentation

- [Build, run, Tailscale, administration, backups and recovery](docs/operations.md)
- [Consistency and interruption recovery](docs/consistency.md)
- [Storage interface and provider configuration](docs/storage.md)
- [Threat model](docs/threat-model.md)
- [LLM context](docs/llm.md) and [source map](docs/source-map.md)
- [Maintenance tools and CI](docs/maintenance.md)
- [Repository instructions](AGENTS.md)

Maintenance: `python3 scripts/docs.py {create,update,delete,check,review} --help`; follow `.agents/skills/maintain-docs/SKILL.md`. CI runs correctness/security checks and disposable deployments; it does not deploy or publish images.
