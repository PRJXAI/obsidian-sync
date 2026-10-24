# Repository maintenance

Read [LLM context](llm.md) and [AGENTS.md](../AGENTS.md). All first-party implementation, tests and automation are Rust. The `xtask/` workspace crate owns documentation, infrastructure, security, image/SBOM and release-content tooling. Shell scripts are four-line launchers, not independent implementations. Python is not permitted. Node/npm are confined to the pinned upstream Commonlib/PouchDB compatibility bridge; neither ships in the runtime.

## Documentation lifecycle

```sh
cargo xtask docs check
cargo xtask docs create docs/topic.md --title 'Topic'
cargo xtask docs update docs/topic.md --from-file /path/to/reviewed-content.md
# First move useful content and remove inbound links; committed history is required.
cargo xtask docs delete docs/obsolete.md --reason 'Superseded by topic.md' --yes
cargo xtask sync-generated
# ONLY after reviewing affected authored documents against implementation and tests:
cargo xtask docs review --reason 'Describe reviewed behavior and evidence'
cargo xtask docs check
cargo test --locked -p xtask
```

`docs/review.json` records source fingerprints, not proof that prose is correct. Never acknowledge drift without reading affected implementation, tests and prose. Documentation writes use descriptor-relative no-follow traversal; escapes, symlink parents/targets, hardlinked update targets, untracked/dirty deletion, missing confirmation and inbound links are rejected. Git retains deleted authored history. No network/LLM calls or unattended prose deletion occur.

`config/` is canonical. `cargo xtask sync-generated` deterministically refreshes Kustomize config copies and the source map; it never rewrites authored runbooks. The checker includes [llms.txt](../llms.txt). Source fingerprints/maps include public tracked or non-ignored candidates, including `xtask/` and `.cargo/`, never ignored operator overrides. `.env` variants and local TOML remain ignored except explicit build/policy manifests and shipped templates. Ignore rules do not scrub history. Keep operational receipts and machine profiles outside authored docs.

## CI and acceptance

[CI](../.github/workflows/ci.yml) has eight Rust feature cells, a shared Linux/musl build/test, security, integration and SBOM producers, plus the stable **Required CI** aggregate. Every producer must succeed; missing, skipped, canceled and failed results reject the aggregate. Enforcing that check through repository rules is still owner-side work. Checkouts do not persist credentials; Actions are commit-pinned; default tokens are read-only. No image is published or real infrastructure deployed.

The build job exports checksum-verified runtime/builder archives. Downstream jobs use those exact images. SBOM generation can accept both original archives, validates their saved configuration/layers against the imported images and hashes their original bytes rather than a newly serialized `docker save` archive. Six SPDX/CycloneDX inventories, native libc identity and `materials.json` bind source/locks/images/SBOMs. Source completeness includes the tooling workspace and npm development dependencies. Inventories and content hashes are unsigned, not builder trust or release authorization.

```sh
scripts/check.sh
scripts/check-features.sh
cargo xtask test-livesync
scripts/test-s3.sh
cargo xtask test-reference-couch
scripts/validate-deployments.sh
cargo xtask test-build-context
docker build --target tests .
docker build --target build -t obsidian-sync:builder .
docker build -t obsidian-sync:local .
cargo xtask verify-image
cargo xtask test-livesync --image obsidian-sync:local
SYNC_SECURITY_BUILDER_IMAGE=obsidian-sync:builder scripts/scan-security.sh
cargo xtask scan-supply-chain --platform linux/arm64  # amd64 in CI; findings remain blocking
cargo xtask generate-sbom
cargo xtask verify-release --image obsidian-sync:local --scan-report .work/security/trivy.json
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
scripts/benchmark.sh
cargo xtask test-livesync --benchmark
```

Docker fixtures require a local Unix-socket daemon. Kubernetes tests must enter through `scripts/smoke-kubernetes.sh`; Rust creates a disposable kind cluster and fences every kind/kubectl invocation with its own kubeconfig, including teardown. They verify readiness, writer exclusion and PVC-backed restart, not production CNI enforcement. Real GCS/Azure accounts, GUI/mobile Obsidian, private TLS/ACLs and operational recovery need separately authorized validation.

## Scanner isolation and evidence handling

Rust inventories pinned Docker/frontend/deployment images and image constants in `xtask/src/`. All severities, UNKNOWN, incomplete/invalid/stale reports and scanner failures remain failures. No ignore list or severity downgrade is introduced. Scanners use caller UID/GID, `HOME=/tmp`, read-only rootfs, dropped capabilities, no-new-privileges, 128 PIDs, two CPUs, 3 GiB memory and a 1536 MiB bounded tmpfs. Inputs are read-only, cache/reports separate, and no Docker socket is mounted. Offline Syft/Gitleaks retain `--network none`. Named container guards remove timed-out containers; captured subprocesses have bounded output and owned process-group cleanup. SIGINT/SIGTERM latch cancellation so work fails while bounded cleanup still runs. Native-only fixtures have inert Docker guards and never invoke container cleanup. Raw scanner stdout/stderr are retained privately rather than printed into CI logs. These controls do not prove a vulnerable vendor tool benign.

Source scans stage only public Git-eligible inputs and reject symlinks. History scans receive an independent bare mirror, no hardlinks/alternates or origin configuration, supporting detached HEAD/all refs while excluding ignored canaries. Use only public source/synthetic data: network isolation does not prevent copying inputs to reports or logs.

Raw reports remain under ignored `.work/security/`. `cargo xtask findings-ledger --platform linux/arm64 --source-revision COMMIT_SHA` produces an artifact/platform-specific local ledger with stable IDs and unresolved native-review categories. All findings begin **under investigation**; this is triage inventory, not an applicability decision or waiver. An approved durable private archive, reviewer ownership and supplier fixes are pending.

Public `security-reports` artifacts now contain only allowlisted count/status summaries. Raw matches, authors, filenames, image configuration environment and provider/tool logs are not copied. Missing inputs are reported as errors, never zero findings. Output validation is defense in depth, not general DLP. Build archives retain one day, public summaries 14 days and SBOM/materials 30 days. SBOM inputs remain explicitly public; no classified inputs may enter this public CI boundary.

`cargo xtask verify-release` requires a trusted complete clean runtime scan no older than 24 hours and checks saved-config/layer/non-root/entrypoint identities before emitting an immutable ID. It is **not** signature verification, whole-chain acceptance or permission to deploy. Current public summaries are not raw runtime reports. `cargo xtask check-release-policy --source-revision COMMIT_SHA` separately fails closed on unset scope/teams, deferred/open milestones, missing reviewed evidence or unverifiable source/release protections; it only reads settings. It does not create rules/CODEOWNERS, issue signatures or certify the underlying closure evidence.

The expanded supply-chain gate still has unresolved upstream-image findings. General egress-sandbox support is explicitly deferred, not waived. Audit schema/sink, framework/data class, provider, crypto, retention and reviewer decisions are pending. See [remediation plan](security-remediation-plan.md), [assessment](regulated-security-assessment.md) and [actual results](results.md). Never suppress advisories, remove tests or claim regulated acceptance to complete a tooling migration.
