# Private Self-hosted LiveSync server

Rust server implementing the **Self-hosted LiveSync / PouchDB CouchDB replication contract**, private behind Tailscale or an internal cluster network. This is a compatible subset for LiveSync, **not Apache CouchDB or a replacement Obsidian client**. MCP is deferred.

- Genuine revision trees, offline conflict branches, branch tombstones, revision reads, checkpoints, bulk replication and bounded change feeds.
- Interchangeable filesystem, S3/MinIO-compatible, native GCS and Azure blob adapters behind one interface. The Obsidian client always selects **CouchDB**, regardless of server storage mode.
- Independently revocable device keys, per-vault grants, request/transfer/concurrency/rate quotas, explicit CORS and persistent single-writer enforcement.
- Distroless static/nonroot runtime: only the Rust executable is added. Private Compose and Kustomize configurations, CI, maintenance tools and LLM documentation.

## First use

Read [operations](docs/operations.md) before provisioning. No real vault is mounted into backend storage.

```sh
docker compose build
# Prepare data ownership for container UID 65532 as documented, then provision OFFLINE:
docker compose run --rm server create-database --name myvault
# Use the printed vault UUID:
docker compose run --rm server issue --vault VAULT_UUID --allow-database-reset
docker compose up -d
```

In the existing **Self-hosted LiveSync** plugin, manually configure a **CouchDB** remote:

- URL: your private Tailscale Serve HTTPS URL, without the database suffix.
- Database: `myvault`.
- Username: the printed `principal` UUID.
- Password: the printed `token` (a generated 256-bit device key).
- JWT: disabled. Skip the optional Apache administrator/configuration checks; the alias is already provisioned. The bootstrap key permits LiveSync's first-device reset/recreate workflow, retaining the prior generation in a bounded archive.

After initialization, revoke the bootstrap key and issue normal keys against the CURRENT vault UUID from `list-databases`; normal keys cannot reset databases. Provision a separate device key for each device. E2EE/compression remain client-managed; the server does not receive encryption passphrases. Future MCP authentication can use the same verifier with its own revocable key, but authorization keys do not decrypt E2EE content.

## Verification

```sh
scripts/check.sh
scripts/check-features.sh
python3 scripts/test-livesync.py     # real Commonlib 0.1.44 / PouchDB 9; disposable data
scripts/test-s3.sh                  # same client tests against real S3-compatible RustFS
python3 scripts/test-reference-couch.py  # optional differential Apache CouchDB 3.5.3 fixture
# After building obsidian-sync:local, test the actual distroless/nonroot runtime:
python3 scripts/test-livesync.py --image obsidian-sync:local
scripts/validate-deployments.sh
```

CI builds shared image artifacts once, runs security/integration gates, and uploads source/runtime/builder SPDX and CycloneDX SBOMs with bound materials. The expanded supply-chain gate currently reports unresolved test/tool-image findings; it is not a clean-release claim.

See [actual results and limitations](docs/results.md). Native GCS/Azure account tests, GUI Obsidian/mobile validation and production CNI/Tailscale access are not implied by the protocol tests. Native CouchDB attachments, general Mango/design-view execution, server administration, physical database purge and history GC are not implemented. Scoped bootstrap reset/recreate is supported without physical history deletion. LiveSync's own chunked binary attachments are supported within configured limits.

## Documentation

- [Authoritative protocol, invariants and compatibility](docs/livesync-protocol.md)
- [Build/run, plugin settings, Tailscale, backups and recovery](docs/operations.md)
- [Original internal-core consistency contract](docs/consistency.md)
- [Storage interfaces and providers](docs/storage.md)
- [Threat model](docs/threat-model.md), [security audit and outstanding supply-chain findings](docs/security-audit.md)
- [LLM build/deploy/operations guide](llms.txt), [LLM architecture context](docs/llm.md), [source map](docs/source-map.md), [maintenance/CI](docs/maintenance.md)
- [Repository instructions](AGENTS.md)

Use `scripts/docs.py` for safe create/update/delete/review operations and `scripts/sync-generated.py` for generated configuration/source-map refreshes. CI does not publish images or deploy to real infrastructure.
