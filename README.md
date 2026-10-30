# Obsidian Sync

**A private LiveSync backend with explicit operational boundaries.**

A Rust implementation of the Self-hosted LiveSync/PouchDB replication contract for teams that want to run their own synchronization service. It preserves revision trees, offline conflicts, tombstones and checkpoints, with revocable device credentials and an optional static distroless container image.

Run the Rust server with a configuration file and private storage. Use a native executable or your preferred approved container runner; Compose and Kustomize are optional deployment examples, not requirements. This is a compatible CouchDB subset, not Apache CouchDB, an Obsidian client or an Internet-facing managed service.

## Choose your starting point

| I want to… | Start here |
|---|---|
| Have a coding assistant guide setup | [Copy the LLM prompt](docs/setup-with-ai.md#copy-this-prompt) |
| Set up my first test vault myself | [Step-by-step getting started](docs/getting-started.md) |
| Choose storage, paths and client settings | [Configuration guide](docs/configuration.md) |
| Operate, back up or recover a service | [Operations runbook](docs/operations.md) |

### Set up with one prompt

Open this repository in your coding assistant and paste:

```text
Help me set up obsidian-sync for a new, disposable Obsidian vault.
Read llms.txt and docs/setup-with-ai.md, then follow that setup contract.
Start with read-only prerequisite checks and ask me to approve a plan.
Default to filesystem + loopback and use the simplest approved runtime.
Compose and Kustomize are optional examples, not prerequisites. Do not read my
real vault or expose secrets. Ask before host, network or cloud changes.
Guide me through private key entry and a synthetic sync check.
```

The assistant asks for your host, storage and private access choices, then prepares an approved configuration. **Device keys stay in your private terminal, not in the LLM conversation.** This is a guided workflow, not an unattended installer or production-readiness claim.

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
- **Container image:** static musl executable, UID/GID 65532, read-only root filesystem, no shell/package manager/configuration/secrets in layers.

SQLite remains local and authoritative in every storage mode. No multi-writer scaling, NFS or shared writable blob namespace between installations.

## Your first vault, in six steps

The minimal filesystem setup runs **one server executable** with a TOML config and a private data directory. SQLite is embedded: no separate database server, cloud account or orchestrator is required.

1. Choose a reviewed executable or source build and a private host with local POSIX storage. Containers are an option; no orchestrator is required.
2. Copy the filesystem template to ignored `config/local.toml`, select native or container-appropriate paths and bind privately. `.env` is only needed for the Compose example.
3. Build if needed, run `check-config` and provision a database alias while the service is stopped.
4. Issue the bootstrap key **privately**; disable the log driver if using a container. Never execute secret-printing issuance through an LLM tool.
5. Start the service, verify readiness, then connect a new disposable Obsidian vault and test a synthetic note.
6. Replace the bootstrap key with separate normal device keys, revoke it, and approve backups before adding important data.

[Follow the complete walkthrough →](docs/getting-started.md)

Readiness is **204** after initialization, **503** while draining. It is not proof of replication or recovery. Use loopback for a same-host test; another device needs approved private HTTPS, not public ingress or Tailscale Funnel. Never mount your Obsidian vault into backend storage.

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
| Optional deployment examples | Compose/Kustomize are provided for convenience; private TLS, durable storage and policy enforcement remain operator responsibilities |
| Cloud storage | Conditional-write/IAM/lifecycle tests are provider-specific; RustFS tests do not certify AWS/GCS/Azure/MinIO |

See [operations](docs/operations.md), [storage](docs/storage.md) and [security](docs/security.md).

## Development, tests and release

The commands below are repository verification, not a list of services/tools every server installation must run. Compose/Kubernetes checks exercise the optional deployment examples.

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

CI uses our published [DevSecOps Syft/Grype images](https://github.com/PRJXAI/devsecops) by source-bound manifest digest. Private pulls use explicit GHCR authentication; package access failures remain blocking, not a reason to fall back to another scanner. Compiler/daemon/service images remain separate. See [build and release engineering](docs/releases.md) for artifact reuse, provenance, package access and publication requirements, and [verification status](docs/results.md) for actual outcomes.

## Documentation

- [Getting started](docs/getting-started.md), [configuration](docs/configuration.md) and [LLM-guided setup](docs/setup-with-ai.md).
- [Operations runbook](docs/operations.md): provisioning, access, probes, upgrades, backups and recovery.
- [Release engineering](docs/releases.md): builds, tool-image adoption and publication.
- [Security and accepted risks](docs/security.md), [trust model](docs/threat-model.md).
- [LiveSync protocol contract](docs/livesync-protocol.md), [storage](docs/storage.md), [consistency](docs/consistency.md).
- [Maintenance](docs/maintenance.md), [verification record](docs/results.md), [source map](docs/source-map.md).
- [llms.txt](llms.txt) and [architecture context](docs/llm.md) for coding/operations agents.

Native attachments, general Mango/design-view execution, global administration and physical purge are outside this subset. MCP, GUI/mobile certification and real-provider disaster-recovery drills remain separate work.
