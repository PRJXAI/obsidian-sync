# Repository maintenance

All first-party code, infrastructure/security/release tooling and tests are Rust in `xtask/`. Shell scripts launch Rust; Node/npm only exercise the pinned upstream compatibility bridge. No Python or first-party unsafe Rust. Read [architecture context](llm.md) and [repository instructions](../AGENTS.md).

## Rust organization

Keep the runtime library and executable in the root crate, and repository automation in the separate `xtask` workspace member. Use cohesive domain modules rather than extra crates or a generic framework for each operation. A `module.rs` can own private children in `module/`; keep imports explicit between siblings and use `pub(super)`/`pub(crate)` for implementation details. Preserve existing public paths through re-exports when moving types.

Keep public-contract integration tests in `tests/` and implementation tests in adjacent `#[cfg(test)]` modules. Formatting, strict Clippy, Rustdoc and every storage feature cell remain checks, not substitutes for the race/cancellation/restart and real-client fixtures.

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
```

Build runtime/builder images before image/SBOM checks; [release engineering](releases.md) gives the order. Use current advisory data for Cargo audit/deny/npm. Benchmark on an idle machine when behavior/performance changes; record hardware/workload/sample count and avoid unmeasured speed claims.

CI keeps eight feature cells, Linux/musl tests, real Commonlib/PouchDB/S3/runtime clients, inventories, security and disposable deployments. `Required CI` rejects failed/missing/skipped/canceled producers. Source/release protections and independent operational approval remain distinct from a workflow result.

## Supply-chain maintenance

Syft generates native JSON/SPDX/CycloneDX; Grype matches the exact native inventories offline after a separate DB refresh. Preserve complete Cargo/npm development locks, original archives/config/layers/source/dirty/native identity and all severity/suppressed counts. No matching filter or automatic advisory waiver.

`risk.rs` applies only the owner's exact current-stack snapshot; new findings and missing/error evidence still fail. Review that policy explicitly when recipes, package versions, advisory/fix identities or occurrence limits change. Do not regenerate approval automatically from failing scans. [Security](security.md) defines scope; [scanner contract](scanner-pipeline.md) defines schemas/freshness.

The producer's independent CLI images are adopted only after successful publish/provenance/package-access verification. Keep host Cargo audit/deny until a qualified replacement preserves coverage. Compilers, Engine/BuildKit and RustFS remain separate assets. Live Kubernetes tests and their K3s/k3d/pause assets are retired; retain their history, not active release requirements.

## Isolation and evidence

Only public inputs and synthetic fixtures. Source scanning excludes ignored configuration/data; history uses an independent bare mirror with detached/all-ref coverage. Scanner inputs/root are read-only, output isolated, resources/deadlines bounded and sockets absent. Networking disabled does not prevent output disclosure.

No live Kubernetes checks remain. Kustomize examples are only rendered locally; never install cluster tools, create a cluster or probe/use an operator context as a prerequisite. Keep application authorization, race, cancellation, restart and writer-fencing tests. Public DevSecOps packages need anonymous verification; do not restore a consumer-reader token/private-export workaround.

Public CI outputs are allowlisted summaries/inventories/materials. Raw reports/logs stay private pending an approved durable archive. Caps are not whole-host/provider quotas. Record exact passed/failed/unexecuted checks in [results](results.md); do not infer production, regulatory, native-provider or GUI acceptance.
