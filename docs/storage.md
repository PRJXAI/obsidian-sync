# Storage interface and adapters

`src/storage/mod.rs` defines object-safe `BlobStorage: Send + Sync` with asynchronous `put(BlobInfo, Reader)` and `get(BlobKey) -> Reader`. `Store` wraps `Arc<dyn BlobStorage>`; synchronization code does not branch on provider. `Store::from_adapter` accepts a new implementation for tests/extensions. The factory uses typed `StorageConfig`. All four adapters compile by default; optional Cargo features are `s3`, `gcs`, `azure`, with filesystem always present. MinIO is an S3 implementation, not a different client protocol.

The interface deliberately has **no overwrite, rename, arbitrary path, arbitrary endpoint, listing or final-object delete** operation. Logical rename/deletion live in SQLite. `get` is an internal raw stream; the engine authorizes access first and returns its stored size/digest. A future protocol adapter must apply read deadlines/backpressure and use those integrity attributes, not expose `Store` directly. Storage has no knowledge of HTTP identities.

## Shared contract

- Keys consist of a vault UUID and server-generated object UUID; callers cannot supply filenames or S3 key strings.
- `put` verifies exact length and SHA-256 before publication, rejects oversized content, and cannot replace an existing final object (even with identical bytes). Conflicts are resolved by the engine through read-and-verify when retrying an upload.
- Filesystem and S3 use 64 KiB transfer buffers. Native cloud writers use a 5 MiB multipart buffer and concurrency 1 per upload. The engine permits at most the configured number of uploads, with no unbounded wait queue.
- Content durability precedes SQLite readiness and then reference publication. Errors may be ambiguous; no reference is published unless read-back verification succeeds.
- Startup probes cloud create-only semantics by publishing `a`, attempting to replace with `b`, requiring a conflict, then verifying `a`. Providers lacking guarantees fail startup. Probe objects are one byte and retained, avoiding a required delete grant on final objects.
- `Store::open` (filesystem staging recovery) must only be invoked under installation authority. Its root must be private to that installation. Creating separate metadata databases over the same root/prefix is unsupported.

## Provider implementations

| Adapter | Implementation | Credentials | Persistent state |
|---|---|---|---|
| Filesystem | Safe rustix dirfd/no-follow operations; exclusive staging; fsync; atomic hard-link publication | POSIX service UID | `/data/blobs` plus SQLite |
| S3 / MinIO | Maintained rusty-s3 SigV4 presigning + reqwest rustls; conditional PUT, no redirects/proxy | Mounted `S3_ACCESS_KEY_FILE`, `S3_SECRET_KEY_FILE` | Bucket/exclusive prefix plus SQLite; anonymous local spooling during uploads |
| Native GCS | Apache object_store GCS adapter; verified streaming staging then conditional destination copy | Mounted `GCS_SERVICE_ACCOUNT_FILE` JSON | Bucket/exclusive prefix plus SQLite; cloud temporary upload state |
| Native Azure | Apache object_store Azure adapter; verified block staging then conditional destination copy | Mounted `AZURE_SAS_TOKEN_FILE` (expiring HTTPS-only container SAS, exactly `sp=rcwd`) | Container/exclusive prefix plus SQLite; cloud temporary upload state |

GCS/Azure native APIs do not emulate S3. Local spooling in S3 mode uses `TMPDIR`, so size its writable volume for `max_inflight * max_blob_bytes` plus overhead; Compose's tmpfs is memory-accounted. Cloud staging lives at `PREFIX/staging/VAULT/OBJECT`. Configure a lifecycle for staging objects older than seven days and provider cleanup of abandoned multipart/resumable/block uploads; never apply it to final objects. Operations time out well before that interval. Interrupted remote uploads can temporarily exceed logical allocation accounting; hard provider-side staging quota enforcement is a known limitation. GCS/Azure production acceptance remains blocked until real-provider contract tests pass.

Config examples: [filesystem](../config/filesystem.toml), [S3/MinIO](../config/s3.toml), [GCS](../config/gcs.toml), [Azure](../config/azure.toml). Cloud credential rotation currently requires a service restart. Workload identity/managed identity refresh and S3 temporary session credentials are not implemented; do not claim support. For Azure, use a dedicated private container and an expiring HTTPS-only container-scoped SAS (`sr=c`, exactly `sp=rcwd` for read/create/write and staging cleanup). Account-wide keys/tokens are rejected. Entra/workload identity refresh is future work.

## Testing/extending

The same `contract(Store)` test covers filesystem and all configured cloud providers. `scripts/test-s3.sh` provisions a disposable real S3-compatible RustFS service; it does not claim MinIO/AWS certification. GCS/Azure tests are explicitly ignored without disposable cloud configurations:

```sh
SYNC_GCS_TEST_CONFIG=/private/test-gcs.toml GCS_SERVICE_ACCOUNT_FILE=/private/service-account.json cargo test --locked --test storage_contract gcs_contract -- --ignored --exact
SYNC_AZURE_TEST_CONFIG=/private/test-azure.toml AZURE_SAS_TOKEN_FILE=/private/sas-token cargo test --locked --test storage_contract azure_contract -- --ignored --exact
```

Those tests create and retain objects. Use only dedicated throwaway buckets/containers, never a real vault. Add an adapter by implementing `BlobStorage`, extending typed config/factory and CI feature matrix, and passing exactly this contract plus provider-specific interruption tests. Do not weaken conditional publication to add a provider.
