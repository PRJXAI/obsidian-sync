# Set up with a coding assistant

**One prompt to start a guided setup, not one prompt that silently changes your host.**

Use an assistant that can read this repository and run approved local commands. A chat-only LLM can explain the steps but cannot inspect or configure your machine. You remain in control of installation, network exposure and credentials.

## Copy this prompt

```text
Help me install and configure https://github.com/PRJXAI/obsidian-sync
for a new, disposable Obsidian vault.

Read README.md, llms.txt and docs/setup-with-ai.md at a reviewed repository
revision, then follow that setup contract. Start with read-only prerequisite
checks, ask the setup questions, and show a plan for my approval before writes.
Default to filesystem storage and loopback-only access. Choose the simplest
approved runtime already available: native executable or container runner.
Compose and Kustomize are optional examples, never required prerequisites.
Never read my real vault, expose credentials, or change host/network/cloud
settings without separate explicit approval. Keep security and release blockers
visible. Guide me through private device-key entry and a synthetic sync check.
```

Then answer the assistant's short setup questions. No paid LLM, provider integration or MCP service is required by the server. Use a local or hosted coding assistant according to your own data-handling policy; never give it note contents or secrets as setup context.

## Setup questions

The assistant should establish:

1. **Where/how:** OS/architecture, the exact host and the preferred existing runtime: reviewed executable, source build or container runner. Is it a fresh test or an existing service? Existing services need the [operations runbook](operations.md), not a fresh bootstrap. Do not require Compose/Kustomize unless that example is chosen.
2. **Reachability:** same-host test only, or another device through approved private HTTPS? Which instance name and loopback port are unused?
3. **Storage:** filesystem initially, or an explicitly requested provider? Which new backend data directory is dedicated to this installation? Cloud storage still needs local SQLite and separate provider qualification.
4. **Client:** disposable vault, device count and client-managed E2EE preference. Do not ask for a passphrase, token, Setup URI or real note.
5. **Recovery:** who will own matched encrypted backups and verify restoration before important data is added?

Only ask unresolved questions. A user may provide non-secret choices in one message, for example:

```text
Fresh Linux test host, approved Rust/C build tools already available. Use a
native source build, filesystem storage, a new ./data directory and loopback
port 8080. No Compose or Kubernetes. Start with one disposable vault. Propose
changes first; I will handle keys in my terminal.
```

This example grants no access to an existing vault, cloud account, cluster or host service.

## Contract for the assistant

### 1. Inspect without changing anything

Read [getting started](getting-started.md), [configuration](configuration.md), [operations](operations.md), [security](security.md), [verification status](results.md) and the repository instructions before proposing commands. The code and shipped templates win over remembered behavior.

Check only necessary prerequisite/version/space metadata for the selected runtime. Docker-endpoint metadata is relevant only if a container route is selected. Do not read ignored operator settings, credential stores, existing backend data, personal Obsidian folders or scheduler/session state. If an existing path/service is found, stop and request a scoped plan; do not assume it belongs to this task.

Do not install tools, grant Docker-group membership, run a privileged daemon, switch kube-contexts, open firewall ports or turn on a proxy during inspection. Do not probe the operator's `kubectl`, even with `--client`: host dispatchers can consult current-context credentials before reporting a version. Repository Kubernetes validation enters only through `scripts/smoke-kubernetes.sh` with its disposable configuration, never through an operator context. A checked local Unix Docker endpoint is not permission to operate every object on that daemon.

### 2. Present a small plan and obtain approval

List the exact repository revision, selected runtime/host, instance name, new files/data directory, port, storage profile and verification steps. Include current release/security limitations and distinguish a disposable demonstration from approved important-data use.

Default to the existing filesystem template and the simplest approved runtime. Use an existing reviewed executable or build from source; for containers use a reviewed source build unless an actual qualified application digest is available. Never invent a download/image/tag or treat a scanner CLI image as the server. Compose and Kustomize are optional examples, not installation requirements. Rust/C prerequisites are needed for a native source build, Docker for a Docker route, and Node only for repository client tests.

Ask separately before privileged ownership changes, package installation, a real provider/account, private HTTPS/ACL changes, an existing installation or important data. A generic “set it up” is not permission to overwrite files or disable a check.

### 3. Configure only the approved new installation

Follow [the walkthrough](getting-started.md) and canonical templates. Create `config/local.toml` only if absent and approved; create `.env` only when the optional Compose example is selected. Keep local choices untracked; confirm ignore behavior without reading secrets. Never commit operator overrides or credential material.

For native execution use absolute host paths, a non-root service user and a loopback listener. For containers explain `/data` versus host mounts and preserve UID/GID 65532, read-only root and host loopback binding. Keep one writer and private backend directories in both cases. Never mount the user's Obsidian vault into backend storage.

Use the real executable's `check-config` command. Use `docker compose config --quiet` additionally only when the Compose example is selected. Report what they check: configuration validation does not probe storage, issue a key or prove replication. `verify-storage`, starting a cloud adapter and cloud contract tests **write probe objects**; they are not dry runs.

No new shell/Python setup program or speculative installer is needed. Use existing commands; all first-party repository automation remains Rust in `xtask`.

### 4. Keep secrets out of model context

Provisioning an alias returns a non-secret vault UUID. **Issuing a key prints its secret once.** Do not run `issue` through a tool that captures stdout into this conversation, even if the container uses `--log-driver none`.

Give the human the exact stopped-service command and approved configuration path. For containers, also disable the log driver and use the correct approved mounts. The human runs it in a private terminal, stores the credential securely and enters it into the plugin. A separate trusted secret-capable workflow may replace that step only if it never returns secret values to the model or logs.

Never request or echo device tokens, bearer headers, provider credentials, private keys, signed URLs, E2EE passphrases, security seeds or Setup URIs. Do not “verify” credentials by reading the private file or running verbose authenticated requests. Ask for non-secret confirmation or sanitized status codes instead. `docker logs` is not a safe way to recover one-shot credentials.

### 5. Verify in stages

1. Validate settings and provision the approved new alias while the service is stopped.
2. Wait for the human's private bootstrap-key step; start only the approved server instance and check loopback liveness/readiness.
3. If another device is involved, stop until private HTTPS and access controls are separately approved and verified. Preserve existing proxy mappings. No public ingress or Tailscale Funnel.
4. Guide manual plugin configuration: CouchDB, root URL, alias, principal UUID/password token, JWT off. Skip unsupported Apache administrator auto-fixes.
5. Have the human create a synthetic note in the disposable client and confirm replication, not paste note content into chat. An HTTP 204 alone is not sync verification.
6. Explain first-device reset/archive behavior, obtain the current vault UUID, guide normal per-device key issuance and bootstrap revocation, and verify an approved restart.
7. Leave important-data onboarding blocked until the operator has approved the storage/security profile and matched encrypted backup/restore procedure.

Never fix a failed setup by deleting backend files, changing SQLite manually, removing the writer lock, resetting an existing vault, sharing credentials, widening CORS or increasing limits without review. No final-blob/revision/tombstone/replay GC exists. E2EE belongs to the clients; server authentication keys cannot recover lost encryption material.

## What a useful handoff looks like

Return a short, secret-free summary:

- Reviewed revision, runtime/host/profile and approved instance/paths, without private configuration values.
- Files created and exact checks actually executed, with status codes or classified failures.
- Whether only availability passed or a human-confirmed synthetic sync/restart also passed.
- Whether bootstrap revocation, per-device configuration, private HTTPS and backups are complete or still pending.
- How to stop/restart that server instance and where the operator runbook lives.
- Any blocked checks, manual actions or remaining release/provider/security limitations.

Do not claim tests you did not run, fabricate credentials/digests, call an accepted-risk result vulnerability-free or infer production approval. The current DevSecOps package-access and pause-inventory gates remain separate from a local source-build demonstration. See [release engineering](releases.md).

A documentation update or this prompt is not an unattended installer, a live GUI/mobile test, a cloud/provider certification or permission to deploy real infrastructure.
