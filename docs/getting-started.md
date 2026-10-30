# Your first synchronized vault

**Run the server, configure a new test vault, verify synchronization.**

Compose and Kustomize are optional deployment examples, not prerequisites. The server needs a TOML configuration, private persistent storage and one running process. Prefer guided setup? [Copy the LLM prompt](setup-with-ai.md#copy-this-prompt).

```mermaid
flowchart LR
    A[Choose an approved runtime] --> B[Validate server configuration]
    B --> C[Provision database and private key]
    C --> D[Connect a disposable Obsidian vault]
    D --> E[Verify sync and rotate bootstrap key]
    E --> F[Approve backups before important data]
```

## Choose how to run it

| Route | What you need | Instructions |
|---|---|---|
| Native executable | An existing reviewed binary, or Rust/C build prerequisites for a source build | Continue below |
| Container without Compose | Docker and the source-built static/nonroot image | Adapt the reviewed runtime mounts/security settings to your approved container runner |
| Compose example | Docker plus the Compose plugin | [Optional Compose deployment](operations.md#compose-example-provision-before-starting) |
| Kubernetes example | Your own explicitly approved cluster/storage/TLS plan; repository validation is render-only | [Optional Kubernetes deployment](operations.md#kubernetes-example) |

Do not install a deployment tool just to follow an example. There is no verified public application image or downloadable binary advertised here: use a reviewed build, not a guessed image tag or install URL. Node is only needed for repository compatibility tests, not to run the Rust server.

Start with filesystem storage. Cloud storage is optional and still needs local SQLite, an exclusive provider namespace and separate provider qualification. The client always selects **CouchDB**, not the server's blob provider.

## 1. Obtain a reviewed build

For a source build, first approve/check the pinned Rust toolchain and C build prerequisites. Do not install them or change the host without permission.

```sh
git clone https://github.com/PRJXAI/obsidian-sync.git
cd obsidian-sync
cargo build --release --locked -p obsidian-sync-server
```

Select a reviewed repository revision before deployment. The command creates `target/release/obsidian-sync-server`. If you already have an approved binary, use its actual path in the commands below instead.

Inspect only the necessary prerequisites and available disk space. Do not proceed on a nearly full host or treat a successful build as full release qualification; read [security](security.md) and [verification status](results.md).

## 2. Configure a fresh filesystem installation

If `config/local.toml`, `data/` or an existing service is present, **stop** and obtain an existing-installation plan. Do not overwrite operator settings or start another writer.

For a fresh checkout:

```sh
cp config/filesystem.toml config/local.toml
mkdir -m 0700 data
```

Edit these three fields in the ignored `config/local.toml`, leaving the other template settings intact:

```toml
listen = "127.0.0.1:8080"
metadata_dir = "/ABSOLUTE/PATH/TO/obsidian-sync/data/metadata"

# Keep the template's [http] and other settings.
[storage]
kind = "filesystem"
root = "/ABSOLUTE/PATH/TO/obsidian-sync/data/blobs"
```

Replace the example paths with the actual new backend location. TOML does not expand `$PWD` or `~`. Native storage paths must be absolute; use a non-root service user with private directories it owns. UID/GID 65532 belongs to the container example, not a requirement to create that host user.

The backend directory is **not your Obsidian vault**. Never mount or point backend storage at a folder containing your notes. Use the same config/data paths for serving and administration.

```sh
./target/release/obsidian-sync-server --config config/local.toml check-config
```

Expected output: `configuration valid; Self-hosted LiveSync CouchDB adapter enabled`.

This only validates settings: no SQLite/storage is opened and no listener starts. It does not establish correct ownership, TLS, provider access or synchronization. See [configuration](configuration.md) for the complete settings guide.

## 3. Provision a database and private bootstrap key

With no server process running:

```sh
./target/release/obsidian-sync-server --config config/local.toml create-database --name myvault
```

Keep the returned vault UUID locally. `myvault` is a database alias. Do not invent an administrator account or use `create-vault`, the legacy internal-core command.

### Human-only private key step

**Run this in a private terminal, not an LLM tool or recorded/shared terminal.** It prints the secret once. Replace `VAULT_UUID`:

```sh
./target/release/obsidian-sync-server --config config/local.toml issue --vault VAULT_UUID --allow-database-reset
```

Store the printed `principal` and `token` securely and enter them into the plugin yourself. Never paste them into chat, tickets, screenshots or agent tool output. A separate trusted secret-handling workflow is acceptable only if values stay out of model context and logs.

For containers, also disable the log driver for issuance: use the [log-disabled container command](operations.md#private-container-key-issuance) with the exact approved config/data/credential mounts. `--log-driver none` does not prevent an LLM tool from capturing stdout, so the human-only rule still applies.

Bootstrap reset is only for initial client setup. It **archives**, rather than deletes, previous generations and changes the vault UUID. It is not a generic repair or physical purge command.

## 4. Start and check the server

In one terminal:

```sh
./target/release/obsidian-sync-server --config config/local.toml serve
```

In another:

```sh
curl -i http://127.0.0.1:8080/health/live
curl -i http://127.0.0.1:8080/health/ready
```

Both return **204** after successful startup; readiness returns **503** while shutting down. Availability is not proof of replication or backup recovery. To stop a foreground server, send Ctrl+C and wait for it to exit before any administration.

For a client on another device, stop here until private HTTPS and access controls are approved and tested. [Tailscale Serve](operations.md#private-tailscale-https) is one optional example, not a server dependency. Preserve existing proxy mappings, use an unused listener, and never expose port 8080 publicly or enable Funnel.

## 5. Connect Obsidian

Create a **new disposable Obsidian vault**, with other sync engines disabled for it. In Self-hosted LiveSync choose **Configure a remote manually → CouchDB**.

| Plugin setting | Value |
|---|---|
| URL | Approved private HTTPS root URL, without `/myvault`; loopback only for a same-host test |
| Database | `myvault` |
| Username | Bootstrap `principal` UUID |
| Password | Bootstrap `token`, entered privately |
| JWT | Disabled |
| Remote type | CouchDB, including when server blobs use S3/GCS/Azure |

Never send credentials over remote plaintext HTTP. Native CouchDB attachments/admin APIs are not part of this subset; LiveSync's chunking is supported within limits. The [protocol contract](livesync-protocol.md) records tested upstream versions; live desktop/mobile GUI certification is separate.

Skip Apache administrator/configuration auto-fixes in “Check server requirements”. Use the ordinary connection test against the provisioned database. Choose E2EE/compression in the client and separately back up its passphrase/security seed: a server key cannot decrypt encrypted notes.

Initialize only this disposable database. Do not select “Overwrite Server” against important data as a troubleshooting shortcut.

## 6. Replace the bootstrap key

After a synthetic test note synchronizes, pause the client, stop the server and list the database:

```sh
./target/release/obsidian-sync-server --config config/local.toml list-databases
```

Use the **current** UUID for `myvault`, not the pre-reset UUID. In your private terminal, issue a normal device key using the same executable/config:

```text
issue --vault CURRENT_VAULT_UUID
```

Omit `--allow-database-reset`. Update the plugin credentials privately, revoke the bootstrap principal, then start `serve` again:

```sh
./target/release/obsidian-sync-server --config config/local.toml revoke --principal BOOTSTRAP_PRINCIPAL_UUID
```

Every additional device gets its own normal key for that current database, issued while the service is stopped. A Setup URI may contain sensitive settings: do not share it with an assistant or reuse its credential across devices.

## Know when setup is finished

- Readiness is 204 and the ordinary plugin connection test succeeds.
- A synthetic note appears on a second disposable client with its own key and matching E2EE settings, if testing multiple devices.
- The same data remains available after an approved server restart.
- The bootstrap key is revoked; ordinary device keys lack reset permission.
- A matched encrypted backup/restore plan and the storage/security profile are approved before important data is added.

Use an existing approved process manager or deployment example when you need unattended startup. No particular orchestrator is required, and none of these observations replaces security/release or provider-native qualification.

## If something fails

| Symptom | Check next |
|---|---|
| Cannot connect | Correct runtime/host/port and loopback probes before the proxy |
| 401 | Principal UUID as username, correct device token/server; never paste credentials into diagnostics |
| 403 | Vault grant, revoked/old-generation key or unapproved Origin; do not disable authorization/CORS |
| Database missing | Provisioned alias and current active generation, not an unrelated replacement vault |
| Admin command reports busy | Stop the writer; never delete `writer.lock` or bypass the process lock |
| Permission denied | Correct native ownership/absolute paths, or exact container mounts and UID; no root/world-writable workaround |
| Body/request limit | Reduce client batch size first; normal batches of 25 with a modest queue are a useful starting point |
| Plugin administrator checks fail | Unsupported Apache administrator APIs are intentional; skip automatic fixes |
| Quota/storage exhausted | Retained revisions/archives count; do not delete blobs or internal SQLite rows |

Request sanitized categories/status codes, not note-bearing logs, tokens or raw provider errors. See [configuration](configuration.md), [operations](operations.md) and [security](security.md) for recovery and optional deployment/provider choices.
