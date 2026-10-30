# Repository maintenance

Read [LLM context](llm.md) and [AGENTS.md](../AGENTS.md). All first-party implementation, tests and automation are Rust in `xtask/`. Shell scripts are four-line launchers. No Python. Node/npm are confined to the pinned upstream Commonlib/PouchDB compatibility bridge and never ship in the runtime.

The incremental cleanup backlog and execution rules are in the [simplification checklist](simplification.md).

## Documentation lifecycle

```sh
cargo xtask docs check
cargo xtask docs create docs/topic.md --title 'Topic'
cargo xtask docs update docs/topic.md --from-file /path/to/reviewed-content.md
# Preserve useful prose and remove inbound links first; committed history is required.
cargo xtask docs delete docs/obsolete.md --reason 'Superseded by topic.md' --yes
cargo xtask sync-generated
# ONLY after reviewing implementation, tests and affected authored pages:
cargo xtask docs review --reason 'Describe reviewed behavior and evidence'
cargo xtask docs check
cargo test --locked -p xtask
```

The review manifest records fingerprints, not proof that prose is correct. Writes use descriptor-relative no-follow traversal; escaping/symlink parents/targets, hardlinked updates, untracked/dirty deletion, missing confirmation and inbound links are rejected. No network/LLM calls or unattended deletion occur. Git retains authored history.

`config/` is canonical. Generated Kustomize copies/source map are deterministic and never rewrite authored runbooks. Link checks include [llms.txt](../llms.txt). Fingerprints/maps include public tracked/non-ignored candidates, including `xtask/` and `.cargo/`, not ignored operator overrides. Ignore rules do not scrub Git history. Operational receipts and machine profiles stay outside authored docs.

## CI and evidence

[CI](../.github/workflows/ci.yml) runs eight Rust feature cells, one shared Linux/musl build/test, SBOM generation, security and integration, plus **Required CI**. Every producer must succeed; missing/skipped/canceled/failed results reject the aggregate. Source/release protections and actual reviewer teams remain owner-side work. Checkouts do not persist credentials, Actions are commit-pinned and tokens read-only. No image publication or real deployment occurs.

The build job exports checksum-verified runtime/builder archives. SBOM generation consumes those exact archive bytes, checks config/layers and emits **native Syft JSON + SPDX + CycloneDX** for source/runtime/builder, native libc identity and bound materials. Both native and CycloneDX source inventories must include Cargo/workspace/npm development lock graphs. The security job consumes those native SBOMs with Grype offline; it does not rebuild/re-catalog them. Declared image scanning uses Syft registry retrieval followed by offline Grype. Full details, command order, suppression accounting and receipt validation: [scanner pipeline](scanner-pipeline.md).

```sh
scripts/check.sh
scripts/check-features.sh
cargo xtask test-livesync
scripts/test-s3.sh
cargo test --locked --test couch
scripts/validate-deployments.sh
cargo xtask test-build-context
docker build --target tests .
docker build --target build -t obsidian-sync:builder .
docker build -t obsidian-sync:local .
cargo xtask verify-image
cargo xtask test-livesync --image obsidian-sync:local
cargo xtask scan-sources
cargo xtask generate-sbom
cargo xtask scan-sbom --sbom-dir .work/sbom
cargo xtask verify-release --image obsidian-sync:local --scan-report .work/sbom/runtime.scan.json
cargo xtask scan-supply-chain --platform linux/amd64
# After all registry/generated scan receipts exist; raw baseline remains private:
cargo xtask dependency-baseline --platform linux/amd64
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
scripts/benchmark.sh
cargo xtask test-livesync --benchmark
```

`scripts/scan-security.sh` is the Rust source/secret → Syft generation → Grype scan convenience path. CI separates generation and consumption through original bound artifacts. Grype is the sole image vulnerability scanner. The owner retired Trivy, its comparison commands/image pin and the transition gate. The inventory has nine active images; unused experimental Go/Git compiler bases and the external CouchDB image are retired. Historical baseline reports remain evidence, not a reviewed advisory closure; current Grype findings/errors still fail the security job and Required CI.

The local-only `rebuild-tool` experiment/framework is retired; normal CI uses unchanged pinned supplier tools. Preserve historical private candidate/compiler evidence and unresolved findings; retirement is not remediation or independent acceptance. See [scanner pipeline](scanner-pipeline.md).

`tests/couch.rs` already exercises the real Rust router with synthetic in-process requests and temporary SQLite/filesystem storage. The eight-cell Rust matrix runs it through the normal workspace test command; no extra mock server, wrapper command or duplicate CI step is needed. Full Commonlib/PouchDB tests against native Rust, S3-backed Rust and the runtime image remain required. Historical reference-CouchDB measurements are not current independent oracle coverage.

## Isolation and failure behavior

Fixtures require a local Unix-socket Docker daemon. Kubernetes tests must enter through `scripts/smoke-kubernetes.sh`. Rust creates/deletes a disposable kind cluster and fences every kind/kubectl command with a private kubeconfig, including teardown. Wait for pod **Ready**, not just phase Running, before execution and after replacement. Verify private readiness, classified second-writer denial and PVC restart; this is not CNI enforcement or a provider DR drill.

Scanner roots/inputs are read-only, resources/time/tmpfs bounded, capabilities dropped, no-new-privileges enabled and no Docker socket mounted. Grype analysis is offline; only separate DB retrieval and Syft registry cataloging have networking. Each invocation receives an isolated output scratch directory, never a writable alias to inputs/earlier evidence. Host Rust validates and copies only expected bounded regular JSON files. Tool JSON is limited to 64 MiB and two million structural tokens; server HTTP JSON limits are unchanged.

SIGINT/SIGTERM latch cancellation: owned work fails while bounded cleanup remains runnable. Subprocess outputs are bounded; owned process groups and named containers are fenced on timeout. Native-only fixtures have inert Docker guards. Raw provider/tool errors are private, not printed into public CI logs. Source/history Gitleaks retain redaction and minimized mounts: Git-eligible source candidates, independent bare mirror, no local hardlinks/alternates/origin configuration, detached/all-ref coverage and ignored-file canaries.

Public security artifacts are count/status summaries only. Raw matches/logs and local triage/comparison ledgers require an approved durable private archive, still pending. Public inventory/materials uploads have explicit file allowlists. All inputs remain public source/images or synthetic fixtures: these controls are not general DLP or proof that suppliers are benign.

## Acceptance remains blocked

All reported severities, Unknown/Negligible, suppressed matches, incomplete/stale/substituted reports and scanner errors remain failures. No severity threshold, `--only-fixed`, advisory ignore or automatic VEX waiver. Runtime content receipts bind hashes/config/layers through a trusted channel; they are not signatures, builder trust or release authorization.

Current Grype matches remain blocking. The historical 27 baseline-only asset/advisory pairs are not declared fixed; the retired scanner's comparison policy is no longer a CI dependency. General egress-sandbox support is deferred. Actual protection/reviewer configuration, private raw-evidence archival, audit schema/sink, framework/data class, provider IAM, crypto/retention and independent operational acceptance remain open. See [results](results.md), [assessment](regulated-security-assessment.md) and [remediation plan](security-remediation-plan.md). Never suppress findings or remove checks merely to complete this migration.
