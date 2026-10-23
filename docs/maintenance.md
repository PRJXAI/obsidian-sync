# Repository maintenance

Read [LLM context](llm.md) and [AGENTS.md](../AGENTS.md). Skills are versioned in `.agents/skills/`: `maintain-docs` and `security-release`. Documentation lifecycle tools do not make network/LLM calls or run unattended destructive edits. Security/client checks deliberately fetch public packages/advisories and run disposable local services.

## Documentation lifecycle

```sh
# Detect broken links, unreviewed drafts and drift in implementation/config/CI sources.
python3 scripts/docs.py check
python3 scripts/docs.py create docs/topic.md --title 'Topic'
python3 scripts/docs.py update docs/topic.md --from-file /path/to/reviewed-content.md
# First move useful content and remove inbound links; deletion requires tracked history.
python3 scripts/docs.py delete docs/obsolete.md --reason 'Superseded by topic.md' --yes
# Refresh generated config copies and LLM source map.
python3 scripts/sync-generated.py
# ONLY after reviewing affected authored documents against changed sources:
python3 scripts/docs.py review --reason 'Describe reviewed behavior and evidence'
python3 scripts/docs.py check
python3 -m unittest discover -s tests -p 'test_*.py'
```

`docs/review.json` records reviewed source fingerprints, not proof that prose is correct. Never acknowledge drift without reading the implementation, tests and affected prose. The tool refuses path escapes, direct symlink targets, untracked deletion, missing confirmation and inbound links. Deletions remain recoverable through Git. Do not call documentation stale solely because it is old. This initial repository had no pre-existing documentation to delete.

`config/` is canonical; generated Kustomize config copies and `docs/source-map.md` are checked in and regenerated deterministically. Authored consistency, threat model, operations, storage, LLM context, root [llms.txt](../llms.txt) and results pages are not automatically rewritten. The link checker includes llms.txt. Source maps and review fingerprints include only tracked or non-ignored source candidates, never ignored local TOML/environment overrides. `.env` variants and `*.toml` are ignored except the root public environment template, required build/policy manifests and explicit shipped config templates. Ignore rules do not untrack files or scrub history; copy deployment examples to ignored local overrides before entering real settings. Machine profiles and deployment-specific receipts do not belong in versioned documentation.

## CI and release gates

[GitHub CI](../.github/workflows/ci.yml) is read-only and does not publish/deploy. Five jobs cover the eight Cargo feature combinations, one shared Linux/musl build/test, security, integration and SBOM generation. The build job exports checksum-verified runtime/builder archives; downstream jobs import those exact artifacts instead of independently rebuilding them. Checkouts do not persist credentials, Actions are commit-pinned and jobs have bounded timeouts. Security runs fresh RustSec/deny, Python regression/doc checks, source/history secrets, runtime AND populated-builder scans, trusted runtime-to-release content verification and all declared public build/test/scanner-image scans. Integration runs actual Commonlib/PouchDB against native Rust, RustFS-backed Rust, the shared distroless runtime and Apache CouchDB, npm audit, rendering and disposable Compose/kind smoke tests. The independent SBOM job emits source/runtime/builder SPDX and CycloneDX, validates complete Rust/npm test lock graphs and uploads a bound source/image/lockfile/materials manifest. Scanner reports upload even on failure. **The expanded supply-chain gate currently fails on unresolved upstream image findings; do not suppress it or describe CI as clean.** See [audit](security-audit.md). Native cloud/provider accounts and GUI/mobile Obsidian validation remain separate authorized acceptance checks. Test-only Node dependencies are pinned, installed with lifecycle scripts disabled and excluded from source fingerprints/container context.

```sh
scripts/check.sh
scripts/check-features.sh
python3 scripts/test-livesync.py
scripts/test-s3.sh
python3 scripts/test-reference-couch.py
scripts/validate-deployments.sh
docker build --target tests .
docker build -t obsidian-sync:local .
python3 scripts/verify-image.py
python3 scripts/test-livesync.py --image obsidian-sync:local
scripts/scan-security.sh
python3 scripts/scan-supply-chain.py --platform linux/arm64  # amd64 in CI; currently blocked by findings
docker build --target build -t obsidian-sync:builder .
python3 scripts/generate-sbom.py
python3 scripts/verify-release.py --image obsidian-sync:local --scan-report .work/security/trivy.json
scripts/smoke-compose.sh
scripts/smoke-kubernetes.sh
scripts/benchmark.sh
python3 scripts/test-livesync.py --benchmark  # real Commonlib logical operations, release mode
```

Image verification exports an ephemeral container and checks non-root execution, the single `/server` executable, absence of shells/package managers, and no ELF interpreter. Docker-injected hostname/resolver/device marker files are checked separately; they are not application binaries. Scanner reports under `.work/security/` include RustSec, source-candidate/history Gitleaks, runtime image/layer identity, Trivy package inventory and advisory timestamps. Trivy covers runtime OS packages; Cargo audit/deny cover Rust dependencies, since Trivy does not reconstruct a statically linked Rust dependency graph from this binary.

CI actions and test/runtime/scanner/SBOM images and the BuildKit frontend are pinned. `.work/sbom/` contains six SPDX/CycloneDX inventories, native-toolchain identity and `materials.json`; the source scan stages only explicit public dependency manifests, never configuration/secrets/data. Rust's bundled musl is distinct from builder OS musl: preserve its archive identity and review upstream backports. Runtime and Cargo scans alone do not cover every native-code advisory. `verify-release.py` requires a trusted clean runtime report no older than 24 hours and compares saved-config/layer identities; it is not a signature verifier. Build archives are retained one day, scan reports 14 days and SBOM/materials 30 days; obtain them through authenticated CI/operator channels. Before updating toolchain, dependencies or image digests: read release notes/advisories, regenerate Cargo.lock deliberately, run ALL checks, and update measured results. Never loosen scanner severity, add advisory ignores or remove failing tests to achieve a green release. The Google Debian Distroless CA advisory found during implementation was addressed by choosing an updated pinned Chainguard static distroless base, not by suppressing the finding.

Smoke/scanner bind mounts use `.work/` inside the checkout so they also work with Colima's shared paths. No real vault, cloud account or current Kubernetes context may be used by default. Core process-restart tests are not power-cut fault-injection or cloud disaster-recovery certification.
