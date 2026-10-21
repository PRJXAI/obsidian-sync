# Build, run and operations

**Not a usable Obsidian plugin server yet.** Supply the plugin name/source; there is no client connection setting that works today. The only HTTP routes are operational probes. Readiness intentionally returns 503. Do not deploy this unfinished protocol integration to a real vault.

## Local development

Requirements: pinned Rust via rustup, C compiler (bundled SQLite), Python 3.11+, Docker/Compose; Kustomize, kubectl and kind for deployment tests. Security tool versions are in CI.

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
scripts/test-s3.sh
scripts/validate-deployments.sh
```

`rust-toolchain.toml` pins stable 1.99.1. Cargo.lock must be included in source-control commits. The final container is digest-pinned Chainguard static (distroless/nonroot); only `/server`, a statically linked musl binary, is added to the base. Base CA certificates/non-root identity files are retained; no application shell, package manager or config/secret is baked in.

## Docker Compose (Linux)

```sh
cp .env.example .env
sudo install -d -o 65532 -g 65532 -m 0700 data
# Review config/filesystem.toml and .env first.
docker compose build
docker compose up -d
curl -i http://127.0.0.1:8080/health/live   # 204
curl -i http://127.0.0.1:8080/health/ready  # 503: protocol_not_configured
```

The parent `/data` mount must be writable by UID 65532. Its service-created `metadata` and `blobs` directories must stay private 0700. Do not mount a real Obsidian vault. HTTP is loopback-bound on the host. Remote access, after future protocol validation, must use private TLS:

```sh
tailscale serve --bg --https=443 http://127.0.0.1:8080
# Inspect private configuration; NEVER run tailscale funnel.
tailscale serve status
```

Use restrictive tailnet ACLs/device approval. Tailnet HTTPS names require the administrator's Tailscale HTTPS setup. The app does not manage Tailscale credentials or enable Funnel. Do not publish another host port or public ingress.

For S3/MinIO edit `config/s3.toml`, set `SYNC_CONFIG_FILE=./config/s3.toml` and credential FILE paths in `.env`, then:

```sh
docker compose -f docker-compose.yml -f docker-compose.s3.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.s3.yml up -d
```

Secret files must be readable by the non-root container UID and not other untrusted users. Docker Compose bind-backed secrets do not reliably remap UID/mode: provision ownership/permissions explicitly (e.g. dedicated group + 0440). Do not put secret values into `.env`. MinIO requires HTTPS remotely, a pre-created private bucket, and support for conditional PUT. S3 credentials need GetObject/PutObject only within the exclusive prefix; never grant bucket administration or cross-prefix access. Provider versioning is strongly recommended.

Native GCS/Azure use their config examples and corresponding mounted secret-file environment variables listed in [storage.md](storage.md). Kustomize overlays include the mounts; Compose users can supply an additional local override mounting only the chosen credential. They remain unvalidated against real cloud accounts. Azure requires an expiring HTTPS-only container-scoped SAS (`sr=c`, exactly `sp=rcwd`) mounted via `AZURE_SAS_TOKEN_FILE`. Grant it only to a dedicated private container; Entra/workload identity refresh is not implemented.

Compose resources: 2 CPUs, 2 GiB memory, 128 PIDs; tmpfs spooling is limited to 1100 MiB and charged against memory. Keep `max_inflight * max_blob_bytes` below the spool and memory budget. Larger settings require explicitly increasing resources, never disabling limits. Filesystem uploads do not use this spool.

## Offline administration

All administration is local; there is no remote admin HTTP API. Commands acquire the same writer lock, so stop the service before running them. Credentials are a core facility, not a plugin connection recipe.

```sh
docker compose stop
docker compose run --rm server create-vault
# Substitute the printed vault UUID. Protect stdout: issue prints a secret ONCE.
docker compose run --rm server issue --vault VAULT_UUID
# For an independently revocable read-only agent:
docker compose run --rm server issue --vault VAULT_UUID --read-only
docker compose run --rm server revoke --principal PRINCIPAL_UUID
docker compose run --rm server verify-storage
docker compose run --rm server checkpoint
docker compose up -d
```

`enqueue-integrity --vault UUID --credential-file /mounted/token --request-id UNIQUE_KEY` durably enqueues a job; use a private credential file containing ONLY its token, not the `principal=`/`token=` labels printed by `issue`. Mount it read-only into a one-shot container. `job-status --job UUID --credential-file /mounted/token` requires a vault grant. Start `serve` to run the single worker. Jobs retain terminal records against their per-vault quota; no purge command exists yet. Retry is exponential with jitter, maximum attempts configured. Inspect logs for safe error classes, not content.

## Kubernetes

The base and overlays use ClusterIP, a dedicated restricted namespace, PVC, Recreate strategy, replicas=1, no service-account token, probes, CPU/memory/ephemeral limits, dropped capabilities, read-only rootfs and NetworkPolicy. There is no Ingress, LoadBalancer, Tailscale operator annotation or HPA. Readiness 503 deliberately prevents Service routing to this unfinished adapter.

```sh
kustomize build deploy/kustomize/overlays/filesystem
kustomize build deploy/kustomize/overlays/s3
kustomize build deploy/kustomize/overlays/gcs
kustomize build deploy/kustomize/overlays/azure
```

Do not apply these to real infrastructure without separate authorization. Before future use: select a local POSIX CSI volume/storage class, replace the image with your privately built immutable digest, configure storage, provision Secret references and narrow cloud egress. Secret names/keys: `sync-s3-credentials` (`access-key`, `secret-key`), `sync-gcs-credentials` (`service-account.json`), `sync-azure-credentials` (`sas-token`). Secret default mode 0440 is readable through fsGroup. Config copies are generated from `config/`; edit originals and run `scripts/sync-generated.py`.

Filesystem data AND metadata use the PVC. **Every cloud mode also requires the PVC for SQLite/WAL, authorization, jobs and cursor state.** S3/GCS/Azure do not make this server stateless. Only temporary spools use emptyDir. Never clone metadata PVCs onto the same writable blob namespace. Never force-delete/detach an old writer on a partitioned node without fencing that node first. Advisory flock protects a shared local metadata directory; it is not a distributed lock. No multi-host writer correctness is claimed.

Disposable validation, never the current kubecontext:

```sh
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
```

The kind script creates/deletes its own cluster and kubeconfig, server-dry-runs all overlays, tests restart, probes and second-writer rejection. Default kind does not enforce NetworkPolicy; run CNI-specific isolation tests before production acceptance.

## Persistent-state inventory and backup

- `/data/metadata/state.sqlite3`, `-wal`, `-shm`: heads/revisions/change cursors, retained tombstones, blob reservations/readiness, allocated quota, credential digests/revocation/grants, scoped idempotency results, job state/ownership/retry counters.
- `/data/metadata/writer.lock`: OS lock inode; not a lease or source of truth. Never unlink/replace it while a process runs.
- Filesystem `/data/blobs/VAULT/OBJECT`: immutable content, plus incomplete deterministic `.stage-OBJECT` files recovered at startup.
- Cloud bucket/container `PREFIX/VAULT/OBJECT`: immutable final content; native cloud staging under `PREFIX/staging/`. One-byte startup probes use nil-vault keys. Separate exclusive prefix for every installation.
- Configuration and provider secrets are independent of data backups; store them securely with the backup recovery key. Device token plaintext cannot be recovered from SQLite; revoke/reissue after a suspected compromise.

For a consistent operator backup, stop all writers and keep them stopped for the entire snapshot. Run the offline command (destination must be absolute and nonexistent):

```sh
docker compose stop
docker compose run --rm server backup --destination /data/metadata-backup.sqlite3
# As an authorized Linux operator, archive metadata-backup.sqlite3 plus blobs/.
# Use encrypted backup tooling; preserve UID/mode; fsync/archive verification is the tooling's responsibility.
```

For cloud modes, retain/snapshot the matching prefix (including immutable historical objects) and SQLite backup together. Do not configure a final-object expiration policy. Bucket contents alone are NOT a backup of sync state. For Kubernetes, stop the controller and take a CSI snapshot plus cloud prefix snapshot, or run one isolated admin pod against the stopped PVC with the same mounts/UID/config. Never back up SQLite by copying its main file while ignoring WAL.

Restore into a fresh private directory/PVC with the service stopped: copy the SQLite backup as `metadata/state.sqlite3`, copy all required filesystem blobs or restore the matching cloud prefix, restore config/secrets/ownership, then start the same binary version. Do not copy a stale WAL over a VACUUM backup. Run authorized integrity jobs and verify expected feeds before exposing clients. The automated `sqlite_backup_restore` test exercises a real SQLite backup restored into a new metadata directory and verifies feed/blob hashes; this is not a tested operator-level cloud/PVC disaster recovery drill.

## Upgrades, rollback and failures

Stop, back up, test restoration in an isolated location, upgrade exactly one writer, and verify integrity. Schema v1 only is supported; unknown schema versions fail before schema modification. No automatic destructive migration exists. Roll back only to a binary compatible with the same schema; otherwise restore a matched metadata/blob backup, with explicit acceptance of changes lost since that snapshot. Do not downgrade just the metadata or reuse a copied metadata database as a second writer.

After crash SQLite replays WAL; old running jobs requeue under the process lock with new claim tokens. Incomplete local filesystem stages are removed on next storage open, while charged reservations/final orphans stay retained. Retry uploads/mutations with the same identity/vault/operation/idempotency key and identical payload. After quota or the fixed revision budget is exhausted, fail closed; finite retention/reclamation/archival tooling is not implemented. Do not repair by editing SQLite/blob files. Missing/corrupt blobs must be recovered from a verified backup before resuming service.
