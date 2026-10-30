# Repository maintenance

All first-party code, infrastructure/security/release tooling and tests are Rust in `xtask/`. Shell scripts launch Rust; Node/npm only exercise the pinned upstream compatibility bridge. No Python or first-party unsafe Rust. Read [architecture context](llm.md) and [repository instructions](../AGENTS.md).

## Documentation lifecycle

Maintain durable operator guidance, not parallel implementation diaries. Transfer useful limits/evidence before retiring pages; Git retains their history. Never erase private failure captures or rewrite historical findings as fixed.

```sh
cargo xtask docs check
cargo xtask docs create docs/topic.md --title 'Topic'
cargo xtask docs update docs/topic.md --from-file /path/to/reviewed-content.md
cargo xtask docs delete docs/obsolete.md --reason 'Superseded by topic.md' --yes
# Mutually linked committed pages may be retired together; external links still block:
cargo xtask docs delete-batch docs/old-a.md docs/old-b.md --reason 'Consolidated operator guide' --yes
cargo xtask sync-generated
cargo xtask docs review --reason 'Describe implementation, tests and authored pages actually reviewed'
cargo xtask sync-generated --check
cargo xtask docs check
```

Deletion requires committed clean targets, explicit confirmation/reason and no outside inbound links. Batch retirement validates the entire bounded set before unlinking; it is not a filesystem transaction. Descriptor-relative no-follow parents and regular-file checks remain. Escapes, symlinks, dirty/untracked targets and duplicates fail. Source review fingerprints acknowledge review, not correctness certification.

`config/` is canonical. Regenerate Kustomize copies/source maps; never hand-edit them. Maps/fingerprints exclude ignored operator files and root scheduler state. Keep actual deployment settings, credentials, operational receipts and machine profiles outside authored docs. Ignore rules do not scrub history.

## Required checks

```sh
scripts/check.sh
scripts/check-features.sh
cargo test --locked -p xtask
cargo xtask test-livesync
scripts/test-s3.sh
cargo test --locked --test couch
scripts/validate-deployments.sh
cargo xtask test-build-context
docker build --target tests .
cargo xtask verify-image
cargo xtask test-livesync --image obsidian-sync:local
cargo xtask scan-sources
cargo xtask generate-sbom
cargo xtask scan-sbom --sbom-dir .work/sbom
cargo xtask scan-supply-chain --platform linux/amd64
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
```

Build runtime/builder images before image/SBOM checks; [release engineering](releases.md) gives the order. Use current advisory data for Cargo audit/deny/npm. Benchmark on an idle machine when behavior/performance changes; record hardware/workload/sample count and avoid unmeasured speed claims.

CI keeps eight feature cells, Linux/musl tests, real Commonlib/PouchDB/S3/runtime clients, inventories, security and disposable deployments. `Required CI` rejects failed/missing/skipped/canceled producers. Source/release protections and independent operational approval remain distinct from a workflow result.

## Supply-chain maintenance

Syft generates native JSON/SPDX/CycloneDX; Grype matches the exact native inventories offline after a separate DB refresh. Preserve complete Cargo/npm development locks, original archives/config/layers/source/dirty/native identity and all severity/suppressed counts. No matching filter or automatic advisory waiver.

`risk.rs` applies only the owner's exact current-stack snapshot; new findings and missing/error evidence still fail. Review that policy explicitly when recipes, package versions, advisory/fix identities or occurrence limits change. Do not regenerate approval automatically from failing scans. [Security](security.md) defines scope; [scanner contract](scanner-pipeline.md) defines schemas/freshness.

The producer's independent CLI images are adopted only after successful publish/provenance/package-access verification. Keep host Cargo audit/deny until a qualified replacement preserves coverage. Compilers, Engine/BuildKit, K3s/tools/pause and RustFS are separate assets.

## Isolation and evidence

Only public inputs and synthetic fixtures. Source scanning excludes ignored configuration/data; history uses an independent bare mirror with detached/all-ref coverage. Scanner inputs/root are read-only, output isolated, resources/deadlines bounded and sockets absent. Networking disabled does not prevent output disclosure.

Kubernetes checks enter through `scripts/smoke-kubernetes.sh`: private HOME/kubeconfig, checked Unix endpoint, loopback API, no default-config updates, pre-existing-name refusal and owned-resource/data cleanup even after cancellation. Verify authenticated persistent identity and writer denial; do not claim CNI enforcement or provider recovery from that smoke.

Public CI outputs are allowlisted summaries/inventories/materials. Raw reports/logs stay private pending an approved durable archive. Caps are not whole-host/provider quotas. Record exact passed/failed/unexecuted checks in [results](results.md); do not infer production, regulatory, native-provider or GUI acceptance.
