# Build, run and operate the LiveSync server

Target: **Self-hosted LiveSync 1.0.39 / Commonlib 0.1.44 / PouchDB 9**, pinned in [protocol contract](livesync-protocol.md). This is a Rust CouchDB-compatible replication subset, not Apache CouchDB. Actual Commonlib/PouchDB and reference-CouchDB fixtures are provided; GUI/mobile Obsidian validation is separate. MCP is deferred. Never test against an existing vault or real infrastructure without separate authorization.

## Build and checks

Rustup installs pinned stable 1.99.1; a C compiler is needed for bundled SQLite. Repository tooling and infrastructure tests use the Rust `xtask` workspace crate. Node 24.20.0+/npm are only for real upstream JavaScript client fixtures; Docker/Compose are needed for container tests; Kustomize, kubectl and kind for disposable deployments.

```sh
cargo build --locked
cargo build --release --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo install cargo-audit --version 0.22.1 --locked
cargo install cargo-deny --version 0.20.2 --locked
scripts/check.sh
scripts/check-features.sh
cargo xtask test-livesync
docker build -t obsidian-sync:local .
cargo xtask test-livesync --image obsidian-sync:local
scripts/test-s3.sh
cargo xtask test-reference-couch
scripts/validate-deployments.sh
```

Node packages are test-only, exact versions/lockfile committed, installed with lifecycle scripts disabled. The final image is digest-pinned Chainguard static **distroless/nonroot**; only the statically linked musl `/server` executable is added. No Node runtime, shell, package manager, application config or secret is included. Test/build stages are not runtime ancestors.

## Compose: provision before starting

```sh
cp .env.example .env
cp config/filesystem.toml config/local.toml
# In the ignored .env, set SYNC_CONFIG_FILE=./config/local.toml.
sudo install -d -o 65532 -g 65532 -m 0700 data
docker compose build
# Locally provision the lowercase database alias, not a filesystem vault directory:
docker compose run --rm server create-database --name myvault
# Use the returned vault UUID. This command deliberately prints a new secret once:
docker compose run --rm server issue --vault VAULT_UUID --allow-database-reset
docker compose up -d
curl -i http://127.0.0.1:8080/health/live   # 204
curl -i http://127.0.0.1:8080/health/ready  # 204; 503 while shutting down
```

Protect credential output; do not forward one-shot `issue` output into centralized logs. No application request logs contain tokens or note bodies. The bootstrap credential's username is its printed `principal` UUID and password is its printed 64-character `token`. There are no default passwords. Keep the service private: Compose binds host loopback. For native execution change `listen` to `127.0.0.1:8080`; container configs use `0.0.0.0` only inside their isolated network.

`/data` must be writable by UID 65532. Service-created metadata/blob roots are private 0700. Never mount a real Obsidian vault or let agents edit internal files. Database aliases are locally provisioned lowercase ASCII names (maximum 80 bytes); `health` is reserved for probes. Remote arbitrary database creation is denied.

### Verified release deployment

Use [the release override](../deploy/compose.release.yml) with an already scanned image imported on the authorized host (e.g. encrypted SSH `docker save`/`docker load`), not an implicit rebuild or registry publication. Keep actual host paths/ports/credentials and operational receipts outside this repository. In the host's private `.env`, set `SYNC_RELEASE_IMAGE` to a unique source-revision tag, `SYNC_RELEASE_REVISION` to that application commit, and the existing `SYNC_DATA_DIR`, `SYNC_CONFIG_FILE`, `SYNC_PORT` settings.

```sh
docker compose -p PRIVATE_PROJECT -f docker-compose.yml -f deploy/compose.release.yml config --quiet
```

Verify imported configuration digest AND filesystem layers against a **trusted** clean runtime scan before starting. Current [Syft/Grype receipts](scanner-pipeline.md) require adjacent `runtime.syft.json` and `runtime.grype.json`; all hashes, source/config/layers, report freshness, DB validity and effective matches are checked. Obtain the complete bundle through an approved private evidence channel. Obtain the raw report through an approved authenticated private operator/evidence channel; current public CI security artifacts contain summaries only, not a deployable raw runtime report. A protected durable raw-evidence archive is still pending. Arbitrary JSON is not an authenticity proof. Reports older than 24 hours, findings including UNKNOWN, missing results and content substitution fail closed:

```sh
# Start with the imported tag/reference from the private .env; use this verified ID for up.
SYNC_RELEASE_IMAGE="$(cargo xtask verify-release --image PRIVATE_IMPORTED_TAG --scan-report /trusted/security-evidence/runtime.scan.json)"
export SYNC_RELEASE_IMAGE
docker compose -p PRIVATE_PROJECT -f docker-compose.yml -f deploy/compose.release.yml up -d --no-build --pull never
```

This helper only verifies runtime content; it does not authorize deployment, verify signatures or override the failing full supply-chain gate. Regulated-production acceptance remains blocked. `cargo xtask check-release-policy --source-revision COMMIT_SHA` is a separate read-only fail-closed preflight: unset scope/teams, deferred milestones, missing closure evidence or unverifiable source/release protections fail. It does not create protections or approve a release.

A failed content verification emits no image reference, so the release override's required-image check rejects it. The scan report binds content, not builder authenticity; require a trusted CI source/materials receipt separately. A local OCI index ID can differ from the saved/imported configuration ID; compare the correct identity levels rather than assuming all Docker IDs are interchangeable. The override requires release identity, forbids implicit pulls, retains the base's loopback binding/security/resource policy and bounds local logs. Administrative key issuance must use `docker run --log-driver none` with the same private mounts and capture its one-shot stdout privately; do not send it through the service's log driver. Never run admin and server writers concurrently.

Preserve existing Serve mappings; choose an unused dedicated HTTPS port rather than resetting/replacing another service. Validate actual TLS, scoped access, restart persistence and a matched stopped-writer baseline. The initial baseline is NOT a recurring/off-host backup policy; configure encrypted ongoing backups before important use. Rollback stops only the new project/listener and retains data, never uses global Serve reset or backend deletion.

### Private Tailscale HTTPS

After the administrator has enabled tailnet HTTPS certificates:

```sh
tailscale serve --bg --https=443 http://127.0.0.1:8080
tailscale serve status
```

This is private Serve, never Funnel. Use restrictive tailnet ACLs and approved devices. Do not publish another host port/public ingress. Basic/Bearer credentials must never cross a remote plaintext connection. The server does not manage Tailscale credentials or enable exposure automatically. Use a root URL (no unstripped reverse-proxy path prefix).

## Configure the existing Obsidian plugin

Use a NEW disposable vault first, with other sync engines disabled. In Self-hosted LiveSync's onboarding choose **Configure a remote manually → CouchDB**. Set:

| Field | Value |
|---|---|
| URL | Private Tailscale Serve HTTPS URL, without `/myvault` |
| Database | `myvault` |
| Username | Generated bootstrap principal UUID |
| Password | Generated bootstrap token |
| JWT | Disabled |
| Remote type | CouchDB, including when the SERVER uses S3/GCS/Azure |

The upstream manual setup's **Check server requirements** step is optional and partly requires Apache administrator/config APIs. Skip its automatic fixes here; this server deliberately does not expose global `_node/_config`, `_users`, `_security` editing or arbitrary JavaScript execution. Proceed with the ordinary connection test against the already provisioned database.

The first-device workflow's “Restart and Initialise Server / Overwrite Server” calls database destroy/recreate. It requires the explicit bootstrap reset capability above. A successful reset ARCHIVES the previous generation instead of deleting its content, then permits reactivation of that same alias. Other clients must be stopped during intentional rebuild. Reset copies grants to a new generation, retires old-generation grants (fencing old uploads), preserves cumulative quota usage, and changes the cursor epoch. At most 16 archived generations are allowed. It does NOT grant global CouchDB administration, create arbitrary aliases, purge objects or erase history. Ordinary write keys cannot reset a database.

After initialization and a verified test note, pause synchronization and replace the bootstrap key with a normal device key:

```sh
docker compose stop
docker compose run --rm server list-databases
# Reset changes the vault UUID: use the CURRENT UUID from list-databases.
docker compose run --rm server issue --vault CURRENT_VAULT_UUID
docker compose run --rm server revoke --principal BOOTSTRAP_PRINCIPAL_UUID
docker compose up -d
```

Update this device's username/password. Generate a Setup URI from the working device to carry compatible encryption/sync settings to other devices, then configure each device with its OWN separately issued principal/token for the same current database. Avoid sharing a bootstrap or regular device credential between agents/devices.

E2EE, compression, chunk hashes and path obfuscation belong to the upstream client. The server stores opaque JSON; an authentication token does not decrypt E2EE notes. Keep the encryption passphrase/security seed separate and backed up securely. Server authentication is Basic (UUID/key) or Bearer (same key verifier), not client-generated JWT. A later MCP service can reuse this verifier with a separately revocable agent key, but still needs the appropriate client-side decryption material for encrypted notes.

Ordinary note rename/move is the client's destination write plus source logical deletion, not an invented atomic file-rename endpoint. Revision trees preserve competing branches and tombstones. Native CouchDB `_attachments` are unsupported; LiveSync's own chunked binary attachments are supported within transfer/document quotas.

### Limits and supported settings

`[http]` is typed/validated. Examples explicitly allow `app://obsidian.md`, `capacitor://localhost`, `http://localhost`; add only the exact origins you need. Wildcards, credentials in origins and remote plaintext origins are rejected; unapproved Origin is rejected on actual requests as well as excluded from CORS responses.

Defaults: 16 MiB request/response, 1 MiB canonical document, 128 documents/page or mutation batch, 8 active execution/response slots, 16 total normal admissions (at most 8 queued, 1-second queue deadline), 32 bounded change-feed admissions, 64 sockets, 90-second connection lifetime, 20-second maximum long-poll. Waiting feeds release execution slots so they cannot starve writes. Uploads await the four-slot storage gate within their operation deadline; a short burst is not falsely reported as exhausted storage. `_changes` POST filters are capped at 256 KiB. JSON also has an independent 65,536 structural-token preflight and conservative 16 MiB working-set charge, including aggregate response construction; bytes alone do not bound allocation. Normal/body parsing has deadlines; JSON/hash work uses a two-slot blocking CPU pool, SQLite/fs sync a bounded pool. Per-principal limit is 6,000 requests/minute with burst 256; global admission is additionally bounded. The integration fixture uses burst 1,024 for its deliberately intense short workload, not disabled rate limits.

Use normal LiveSync batch size 25 and a modest batch queue (e.g. 2). Transfer bounds can require smaller client batches. Byte-limited change pages return resumable `last_seq`/`pending`; keyed bulk reads/mutations fail explicitly when over budget rather than omitting requested documents. Large direct Commonlib calls with more than 128 chunks in one bulk request must be split by their caller or use an explicitly reviewed server batch limit; standard PouchDB replication already batches. Unsupported filters/selectors, Mango/views, purge, general attachments and administrator routes fail explicitly. Supported change selectors are `_doc_ids` and the upstream on-demand `type` equality/inequality form.

Imported revisions (`new_edits=false`) use CouchDB first-body-wins replay semantics: fresh E2EE IV/salt can produce different ciphertext for an identical revision. Replays never replace the immutable stored body or advance its sequence; contradictory ancestry fails. Explicit internal-core idempotency keys remain payload-bound. Normal updates require their parent revision and return conflicts instead of force-overwriting; after an ambiguous normal PUT, re-read the revision before retrying.

## Storage modes

Canonical non-secret templates: [filesystem](../config/filesystem.toml), [S3](../config/s3.toml), [GCS](../config/gcs.toml), [Azure](../config/azure.toml). Copy the selected template to ignored `config/local.toml` before entering deployment-specific settings, and select it through ignored `.env`. Do not put real credentials, endpoints or host paths into versioned examples. Required build/policy TOML manifests and explicit shipped templates remain tracked; other TOML files and `.env` variants are ignored. Ignore rules do not erase already tracked files or history. Metadata remains local and persistent in ALL modes.

For S3/MinIO, pre-create a private bucket, choose an exclusive installation prefix and configure endpoint/region/addressing style. Copy `config/s3.toml` to ignored `config/local.toml`, set `SYNC_CONFIG_FILE=./config/local.toml`, and set credential FILE paths in ignored `.env`:

```sh
docker compose -f docker-compose.yml -f docker-compose.s3.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d
```

Mounted credentials: `S3_ACCESS_KEY_FILE`, `S3_SECRET_KEY_FILE`; require GetObject/PutObject only in the installation prefix. HTTPS required remotely; plain HTTP is accepted only for explicitly enabled literal-loopback tests. Conditional PUT is probed at startup; unsupported guarantees fail startup. MinIO/AWS are not certified merely because RustFS passed.

Native GCS: mounted `GCS_SERVICE_ACCOUNT_FILE`, bucket-scoped service-account IAM. Native Azure: mounted `AZURE_SAS_TOKEN_FILE`, expiring HTTPS-only container-scoped SAS (`sr=c`, exactly `sp=rcwd`). No account-wide Azure key, workload identity refresh or S3 session-token support is claimed. Native providers need separately authorized disposable-account tests before acceptance. Restart after credential-file rotation.

Compose bind-backed secret files must actually be readable by UID/group 65532 and not untrusted users (e.g. dedicated group, 0440); Compose does not reliably remap their ownership/mode. Never place real values in `.env`/config examples. Size S3 anonymous local spooling for `max_inflight * max_blob_bytes`; Compose's 1100 MiB tmpfs counts against its 2 GiB memory budget. Native cloud staging needs a >7-day lifecycle/abandoned-upload cleanup, never applied to final objects; hard remote staging quota enforcement is a known limitation. See [storage](storage.md).

## Local administration and jobs

Stop the service for every local admin command; each acquires the same writer lock. Useful commands:

```sh
docker compose run --rm server list-databases
docker compose run --rm server issue --vault CURRENT_UUID --read-only
docker compose run --rm server revoke --principal PRINCIPAL_UUID
docker compose run --rm server verify-storage
docker compose run --rm server checkpoint
```

`create-vault` remains a legacy internal-core operation; use `create-database --name NAME` for LiveSync. Do not issue credentials to archived vault UUIDs (the CLI rejects this). There is no public archive browser/restore/purge API; archive recovery is an operator backup/restore concern until dedicated reviewed tooling exists.

`enqueue-integrity --vault UUID --credential-file /mounted/token --request-id KEY` durably enqueues a read-only integrity job. The mounted private file contains ONLY its token. `job-status --job UUID --credential-file /mounted/token` requires its current vault grant. Start `serve` to run the bounded worker. Claims are persistent/fenced, retries finite with exponential jitter, and claims round-robin across vaults. Terminal jobs remain within the quota. Archived job records remain persisted but retired grants no longer authorize old-generation inspection. No exactly-once external effects are claimed.

## Kubernetes

Base and filesystem/S3/GCS/Azure overlays provide ClusterIP, restricted namespace/security context, Recreate/replicas=1, a persistent PVC, no service-account token, limits/probes and NetworkPolicy. No public Ingress, LoadBalancer, HPA, Funnel or bundled Tailscale process is installed. The Rust runtime stays binary-only.

```sh
kustomize build deploy/kustomize/overlays/filesystem
kustomize build deploy/kustomize/overlays/s3
kustomize build deploy/kustomize/overlays/gcs
kustomize build deploy/kustomize/overlays/azure
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
```

Smoke tests use disposable resources and an explicit temporary kind kubeconfig, never the current context. The kind script server-dry-runs overlays and verifies PVC restart, readiness and writer exclusion. Its default CNI does NOT prove NetworkPolicy enforcement. Run policy-aware CNI tests before production acceptance.

Before authorized real use: choose a local POSIX CSI class, replace the image with your immutable private digest, configure/provider-test storage, provision Secrets and narrow cloud egress. Secret keys: `sync-s3-credentials` (`access-key`, `secret-key`), `sync-gcs-credentials` (`service-account.json`), `sync-azure-credentials` (`sas-token`). 0440 secret files are readable via fsGroup. Pre-provision users/database through one isolated admin pod while the controller is stopped, then remove it before starting the server. Private remote access still needs HTTPS termination and matching ingress policy; ClusterIP is not itself a TLS proxy.

**Cloud modes require the metadata PVC too.** Only spooling is emptyDir. Never use NFS, clone metadata copies onto one writable blob namespace, force-detach a partitioned writer without fencing its node, or scale to multiple writers. The local file lock is not a distributed lease. Recreate alone is not the runtime fence; the held lock and shared authoritative metadata are.

## Persistent state, backup and tested restoration

- `/data/metadata/state.sqlite3` plus WAL/SHM: core authorization/grants/revocation, blobs/reservations/quota/jobs/replays; schema-v3 Couch aliases/active state, full revision DAG and blob references, current heads/sequences, local `0-N` checkpoints, instance UUID, scoped reset permissions, archived generations and retired grant snapshots.
- `writer.lock`: process-lifetime OS lock inode; never unlink/replace it while running.
- Filesystem `/data/blobs/VAULT/OBJECT`: immutable bodies and bounded deterministic incomplete staging; startup removes incomplete stages under authority.
- Cloud `PREFIX/VAULT/OBJECT`: immutable final bodies, including archived generations; native-cloud staging is separate. Startup one-byte probes are retained.
- Provider credentials, client E2EE passphrases/security seeds, configuration and plaintext device keys are separate recovery material. SQLite stores only token digests; lost plaintext device keys must be revoked/reissued.

Stop all writers for the full operator snapshot. `backup` uses SQLite VACUUM INTO followed by file and parent-directory synchronization; destination must be absolute and nonexistent:

```sh
docker compose stop
docker compose run --rm server backup --destination /data/metadata-backup.sqlite3
# Archive this snapshot plus ALL immutable blobs (active, historical, archived/orphaned).
# Keep writers stopped until the matched blob snapshot is complete; encrypt/verify backups.
```

For cloud modes retain a matching prefix snapshot/provider versioning plus the SQLite backup; bucket contents alone do not contain synchronization/auth state. No final-object expiry policy. For Kubernetes use stopped-writer CSI/prefix snapshots or one isolated admin pod, never copy SQLite's main file while ignoring WAL.

Restore into fresh private directories/PVC with the service stopped: copy the backup as `metadata/state.sqlite3`, restore matching blobs/config/secrets/ownership, and start the same compatible binary. Do not add stale WAL to a VACUUM backup. Tests restore a real Couch snapshot plus copied filesystem blobs into a new installation, authenticate, read/hash content, preserve epochs/checkpoints/archives and reject future cursors from after the snapshot. This is NOT a cloud/PVC operational disaster-recovery drill. A backup also rolls back revocations; after a security incident revoke/reissue keys and rotate provider secrets using a separately verified revocation record.

## Upgrades, rollback and interruptions

Schema v1/v2 migrate transactionally to v3; authorization/core history and existing Couch aliases/revisions are retained. v2 gains active-generation lifecycle state. Unknown newer schemas fail before modification. This migration does not convert legacy core single-head notes into LiveSync metadata/chunk documents.

Stop, back up, test restoration in isolation, upgrade one writer, then verify client replication/integrity before access. Roll back only with a binary supporting the schema; otherwise restore a matched metadata/blob backup with explicit acceptance of post-snapshot changes lost. No downgrade of metadata alone. Old v0.1 binaries cannot open schema v3.

After crash SQLite recovers WAL; old running jobs requeue under the writer lock with new claim tokens. Partial bodies/reservations stay charged; incomplete filesystem staging is removed at restart. Duplicate imports safely resume after lost responses. A reset changes the opaque cursor epoch; stale/future cursors fail, requiring client checkpoint/rebuild coordination, never silent sequence reuse. If interrupted between destroy/recreate, the alias remains inactive across restart: stop the service, list its CURRENT UUID, issue a replacement bootstrap key if necessary, then retry authenticated `PUT /DATABASE` before rebuilding clients. Keep old clients offline during rebuild and rejoin them using LiveSync's normal workflow.

Shutdown marks readiness unavailable, stops new data work, wakes waiting feeds and stops worker claims; drains are bounded. A shutdown timeout is an error, not a false clean completion; unacknowledged requests retry after restart. Published acknowledgements remain durable.

No final-history GC/purge/reclamation is implemented. Per-document tree/leaf/ancestry limits, one-million current-generation sequence budget, retained allocations, local-checkpoint limits and terminal-job quotas eventually require reviewed archival/repair tooling. Do not recover space by editing internal tables/files. Restore missing/corrupt bodies from a verified matched backup instead.
