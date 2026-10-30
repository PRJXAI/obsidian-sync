# Obsidian Sync

**A private LiveSync backend with explicit operational boundaries.**

A Rust implementation of the Self-hosted LiveSync/PouchDB replication contract for teams that want to run their own synchronization service. It preserves revision trees, offline conflicts, tombstones and checkpoints, with revocable device credentials and a static distroless runtime.

Built for **SREs and DevSecOps engineers operating a private, single-writer installation**. This is a compatible CouchDB subset—not Apache CouchDB, an Obsidian client or an Internet-facing managed service.

## Architecture

```text
Obsidian / Self-hosted LiveSync
          │ private HTTPS
          ▼
   Rust replication server ── SQLite metadata + writer lock
          │
          └── immutable blobs: filesystem / S3 / GCS / Azure
```

- **Integrity:** transactional revision publication, first-body-wins replay, retained conflict branches and hash/size-verified create-only storage.
- **Isolation:** per-device random keys, revocable vault grants, exact CORS and bounded admission/transfer/work queues.
- **Operations:** private Compose/Kustomize examples, readiness/liveness probes, offline administration and matched backup/restore procedures.
- **Runtime:** static musl executable, UID/GID 65532, read-only root filesystem, no shell/package manager/configuration/secrets in layers.

SQLite remains local and authoritative in every storage mode. No multi-writer scaling, NFS or shared writable blob namespace between installations.

## Start with a disposable installation

Requirements: Docker/Compose and a private Linux host. Review [the operations runbook](docs/operations.md) before using important data. Never mount an Obsidian vault directly into backend storage.

```sh
cp .env.example .env
cp config/filesystem.toml config/local.toml
# Set SYNC_CONFIG_FILE=./config/local.toml in the ignored .env.
sudo install -d -o 65532 -g 65532 -m 0700 data
docker compose build
docker compose run --rm --no-deps server create-database --name myvault
```

Use the returned vault UUID to issue a bootstrap credential **while the service is stopped**. Key issuance prints a secret once: disable the container log driver and capture stdout privately.

```sh
docker run --rm --network none --log-driver none --read-only \
  --user 65532:65532 --cap-drop ALL --security-opt no-new-privileges \
  -v "$PWD/data:/data" \
  -v "$PWD/config/local.toml:/etc/obsidian-sync/config.toml:ro" \
  obsidian-sync:local issue --vault VAULT_UUID --allow-database-reset

docker compose up -d
curl -i http://127.0.0.1:8080/health/ready
```

Readiness is **204** after initialization, **503** while draining. Compose publishes only loopback. Remote credentials require private HTTPS, for example Tailscale Serve with restrictive ACLs—never Funnel or public ingress.

## Configure Self-hosted LiveSync

Choose **CouchDB** regardless of the server's blob-storage backend:

| Setting | Value |
|---|---|
| URL | Private HTTPS root URL, without database suffix |
| Database | Provisioned alias, such as `myvault` |
| Username | Generated principal UUID |
| Password | Generated device token |
| JWT | Disabled |

Skip Apache administrator/configuration auto-fixes unsupported by this subset. The bootstrap key permits the first-device reset/recreate workflow; it **archives**, rather than purges, the previous generation. After initialization, obtain the current vault UUID, issue normal per-device keys and revoke the bootstrap principal. [Exact onboarding and rotation steps](docs/operations.md) explain this transition.

E2EE/compression remain client-managed. Authentication keys do not decrypt notes; keep encryption passphrases/security seeds separate and backed up.

## Run it responsibly

| Concern | Operational rule |
|---|---|
| Scaling | One writer, one authoritative local POSIX metadata volume; fence a failed node before failover |
| Administration | Stop the service; CLI commands acquire the same persistent writer authority |
| Backup | Match a consistent SQLite snapshot with **all** immutable blobs and separately protected recovery material |
| Retention | No final-blob/revision/tombstone/replay GC; never recover space by editing internal storage |
| Kubernetes | ClusterIP/Recreate/PVC samples; private TLS and policy-enforcing CNI validation remain deployment responsibilities |
| Cloud storage | Conditional-write/IAM/lifecycle tests are provider-specific; RustFS tests do not certify AWS/GCS/Azure/MinIO |

See [operations](docs/operations.md), [storage](docs/storage.md) and [security](docs/security.md).

## Build, test and release

All first-party code and automation are Rust in the workspace and `xtask`. Shell files are thin launchers. Node/npm only exercise pinned upstream Commonlib/PouchDB clients; they do not ship in the runtime.

```sh
scripts/check.sh
scripts/check-features.sh
cargo xtask test-livesync
scripts/test-s3.sh
scripts/validate-deployments.sh
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
```

CI tests eight feature combinations, the actual Linux/musl runtime, genuine clients, S3, persistent restart and writer exclusion. Kubernetes tests always create their own private kubeconfig/cluster; never use the operator context.

Supply-chain checks use **Syft → native SBOM → offline Grype**, fresh RustSec/deny/npm checks and minimized source/history secret scans. The owner accepted a specific investigated stack-risk snapshot on **2026-10-30**; accepted findings remain visible. New findings, missing inventories and scanner failures still block. This is not a vulnerability-free or regulated-production claim.

Our [DevSecOps tool images](https://github.com/PRJXAI/devsecops) are being integrated by verified published digest, not mutable tags or speculative pins. Compiler/daemon/service images remain separate. See [build and release engineering](docs/releases.md) for artifact reuse, provenance, package access and publication requirements, and [verification status](docs/results.md) for actual outcomes.

## Documentation

- [Operations runbook](docs/operations.md): provisioning, access, probes, upgrades, backups and recovery.
- [Release engineering](docs/releases.md): builds, tool-image adoption and publication.
- [Security and accepted risks](docs/security.md), [trust model](docs/threat-model.md).
- [LiveSync protocol contract](docs/livesync-protocol.md), [storage](docs/storage.md), [consistency](docs/consistency.md).
- [Maintenance](docs/maintenance.md), [verification record](docs/results.md), [source map](docs/source-map.md).
- [llms.txt](llms.txt) and [architecture context](docs/llm.md) for coding/operations agents.

Native attachments, general Mango/design-view execution, global administration and physical purge are outside this subset. MCP, GUI/mobile certification and real-provider disaster-recovery drills remain separate work.
