# Security and supply-chain audit — 2026-10-23

## Verdict and scope

**No confirmed vault-isolation bypass or remote code execution was found in the first-party server. One unauthenticated availability flaw was reproduced and fixed. The expanded supply-chain gate is NOT clean.** Successful server/runtime checks do not override outstanding build/test/scanner image findings.

Review scope: the implementation baseline and subsequent remediation source snapshot before publication. This review covered all first-party Rust modules; authentication/authorization and protocol boundaries; revision publication, replay, quota and cancellation paths; filesystem/cloud adapters; persistent jobs and recovery; Cargo/npm lockfiles; Dockerfile, CI, maintenance/test scripts and deployment manifests; source candidates and committed-history secret scans. Public advisory/package/image downloads and disposable local tests were authorized; no real vault, cloud account, cluster, private deployment or registry publication was accessed.

This is a code/configuration review plus executable checks, not a line-by-line audit of every transitive dependency, proof of absence of vulnerabilities, or a review of GitHub organization/branch-protection settings, production ACLs, host patching or cloud IAM. Native provider tests, policy-aware CNI isolation, disaster recovery and GUI/mobile certification remain separate gates.

The follow-up [regulated-environment assessment](regulated-security-assessment.md) separates package matches from reachable paths and evaluates exfiltration, repository enforcement, egress, auditability, crypto and release-policy gaps. It also documents the history-scanner input minimization fix. Do not infer regulatory readiness or malicious behavior from this image-count table alone.

## SBOM-first scanner follow-up

Default CI now uses [Syft → native SBOM → offline Grype](scanner-pipeline.md), with original image-archive/config/layer binding, native/CDX lock completeness, isolated per-invocation output and hash-bound content receipts. Trivy and its comparison/transition gate are now retired by explicit owner request. Earlier Grype source/runtime results were zero, but the populated builder had 19 matches (one Critical), and ten of eleven then-declared/comparison images had matches. The earlier same-config comparison retained 27 baseline-only asset/advisory pairs as historical investigation evidence; retirement is not a claim those advisories were fixed. Current Grype findings/errors still block security and Required CI. The Trivy tables below are historical, not claims that the new scanner agrees or that the builder remains clean under every detector. Grype's own image is inventoried/scanned too.

## Rust tooling follow-up

First-party infrastructure, security, documentation, SBOM and content-verification tooling and its regression tests now live in the Rust `xtask/` workspace crate. Shell files only launch Rust. The original audit measurements below are historical; current migration checks are recorded in [results](results.md). npm remains exclusively the pinned upstream client bridge, not infrastructure logic or a runtime dependency.

A stable `Required CI` aggregate now rejects any failed, skipped, canceled or missing producer. A read-only policy preflight rejects unset scope/reviewers, open/deferred milestones and unverifiable protection/approval settings. It neither configures repository enforcement nor signs/authorizes releases. Scanner containers additionally have bounded resources/tmpfs and read-only roots. The findings ledger retains unresolved asset/platform associations without waivers. CI SBOM generation binds the original shared archive bytes, not an independently reserialized save. General egress-sandbox support is explicitly deferred. All remaining A/R acceptance blockers remain open.

## Trust and supply-chain map

1. Untrusted LiveSync/PouchDB clients → private TLS proxy → bounded HTTP transport → persistent credential/grant verifier → vault-scoped revision DAG/checkpoints.
2. SQLite FULL/WAL and immutable blob publication are authoritative. Blob addressing uses generated UUIDs, not document paths. Cloud credentials and backend parents are operator-controlled trust boundaries.
3. Rustup/toolchain, crates.io packages/checksums, build scripts/procedural macros, bundled SQLite and AWS-LC, the Rust target's libc, the C compiler/linker and BuildKit frontend participate in the executable's supply chain. First-party unsafe prohibition does not remove transitive Rust unsafe/C/assembly.
4. Digest-pinned builder/runtime/test/scanner images and commit-pinned Actions reduce substitution but do not establish benign provenance or freshness. Hosted runner images and installed Go/Cargo tools are additional trusted build inputs.
5. Node/Commonlib/PouchDB are test-only. The compatibility contract remains pinned to Commonlib 0.1.44/PouchDB 9; npm lifecycle scripts are disabled. They are not shipped in the runtime.
6. CI builds once and transfers checksum-verified runtime/builder archives to security, integration and SBOM jobs. Authenticated CI artifact delivery is trusted; generated inventories are not signed release attestations.

## Findings and remediation

### A-01 — Authenticated budget depletion without credentials — MEDIUM, fixed

`src/couch/http.rs` previously debited the shared global token bucket before authenticating. An unauthenticated peer able to reach the private listener could spend the budget of every valid device. With a deliberately small **valid** configuration (`burst=4`, `requests_per_minute=1`), one authorized GET returned 200, three anonymous GETs returned 401, and the next authorized GET returned 429; readiness remained 204. This was reproduced only against a disposable loopback server.

Global charging now occurs after token verification and Basic username matching, inside `authenticate`. Connection/execution/admission limits still bound failed authentication; no unbounded task/queue was introduced. Regression test `failed_authentication_cannot_spend_authenticated_rate_budgets` exercises missing/malformed credentials and a valid key with the wrong username, then verifies exactly the remaining valid burst and eventual 429. Private-proxy unauthenticated peer throttling is still recommended; this change does not promise complete DoS immunity or per-vault availability fairness.

### A-02 — Build/test/scanner images were outside the vulnerability gate — MEDIUM control gap, partially remediated / OPEN

The old scan covered runtime OS packages, Rust advisories and source/history secrets, but not builder or test/scanner images. The baseline builder had zlib and musl package matches; old Gitleaks, reference CouchDB and kind images had high/critical package matches. These are not automatically exploitable first-party server vulnerabilities.

Remediation:

- Cargo.lock refreshed across 14 dependencies, including UUID 1.29.0, ICU 2.4, cc 1.10.0 and corresponding supporting crates. RustSec/deny remain clean; no advisory ignores were added.
- Rust 1.99.1 retained and synchronized with the updated Alpine 3.24 builder digest; the populated builder scan is now clean. Helper Alpine upgraded to 3.23.7 and clean.
- Reference CouchDB upgraded from 3.5.0 to 3.5.3; kind node from 1.36.1 to 1.37.0 and CI kind tool to 0.33.0; BuildKit frontend upgraded/pinned to 1.28.0. Syft is pinned to 1.55.0-nonroot.
- `scripts/scan-security.sh` now scans the actual populated builder as well as the runtime and preserves the Rust toolchain libc identity.
- `cargo xtask scan-supply-chain` inventories declared public build/test/scanner images, including Rust tool constants, requires external Dockerfile/frontend digest pins, emits per-image JSON/logs and fails on any severity, UNKNOWN, missing output or scan failure. Scanner containers have no Docker socket and timed-out clients explicitly remove their own containers. CI runs this gate even after earlier failure and publishes allowlisted count/status summaries. Raw reports stay local pending an approved private archive; raw matches/logs are not public artifacts.

**Still open:** current official test/scanner/frontend images contain findings, including the newest stable pins selected here. Updating them reduced exposure but did not eliminate it. The gate must remain failing until patched upstream or deliberately rebuilt maintained artifacts and evidence-based native/platform triage are available. No severity filter, advisory allowlist or `ignore-unfixed` workaround was added.

Current arm64 image package-association counts (C/H/M/L/U); these count package/advisory pairs, not distinct exploitable defects:

| Image | C / H / M / L / U |
|---|---:|
| Runtime and populated builder | 0 / 0 / 0 / 0 / 0 |
| Alpine 3.23.7 helper | 0 / 0 / 0 / 0 / 0 |
| Syft 1.55.0-nonroot | 0 / 4 / 9 / 1 / 2 |
| Trivy 0.76.1 | 0 / 0 / 0 / 0 / 3 |
| Reference CouchDB 3.5.3 | 0 / 65 / 112 / 177 / 2 |
| BuildKit Dockerfile 1.28.0 | 2 / 9 / 15 / 2 / 1 |
| Gitleaks pinned upstream 8.30.1 image | 2 / 70 / 77 / 38 / 6 |
| kind node 1.37.0 | 4 / 215 / 376 / 227 / 17 |
| RustFS 1.0.3 image | 0 / 0 / 0 / 0 / 2 |

These scans used Trivy 0.76.1 with the DB updated 2026-10-23 07:12:39 UTC. The CI gate independently scans linux/amd64; no arm64 counts are asserted for amd64. An upstream OpenSSL 32-bit-only finding does not prove exploitation on the inspected 64-bit platform; feature/platform reachability is not established by version matching alone. Unknown musl and unmaintained OpenPGP matches also need explicit investigation, not silent dismissal.

### A-03 — Static native components need separate inventory — MEDIUM assurance gap, improved / OPEN

The runtime scan sees three Wolfi OS packages and cannot reconstruct the statically linked Rust/C dependency graph. Cargo audit covers Rust advisories, not every upstream libc/SQLite/crypto advisory.

A link-command trace and archive inspection showed that the target uses Rust's **self-contained musl 1.2.5**, not Alpine's installed musl-dev 1.2.6. The Rust 1.99.1 upstream build script explicitly backports CVE-2025-26519, CVE-2026-6042 and CVE-2026-40200 fixes. It would be incorrect to infer an unpatched runtime qsort issue from Alpine package matching or the unqualified string `1.2.5`. No such runtime exploit was demonstrated. The locked SQLite wrapper bundles SQLite 3.53.2; AWS-LC and native libc remain part of the trusted binary.

SBOM output now includes the complete locked Rust graph, **including all npm test dependencies**, runtime/builder inventories, native toolchain archive identity and bound image materials. Completeness checks fail if Syft silently omits locked development dependencies. Native patch-level review and version-to-function reachability remain necessary; the SBOM does not replace them.

### A-04 — Release content binding was manual; CI rebuilt artifacts independently — MEDIUM assurance gap, remediated within trusted-operator model

Local tags and container revision labels alone do not prove that a deployed image is the scanned image. CI now exports one pair of built images, verifies archive checksums on import, and reuses those exact images in the security, integration and SBOM jobs. The source revision is recorded in an OCI label (not treated as an authenticity signature).

`cargo xtask verify-release` checks a **trusted**, complete, clean runtime scan no older than 24 hours against the imported image's saved configuration SHA-256 and layer identities, validates non-root/entrypoint settings, and prints the daemon's immutable image ID. It resolves a tag once and exports by that ID, preventing tag substitution during verification. Tests cover config/layer replacement, findings including UNKNOWN, missing scan results, stale/future reports and OCI-index/config identity differences. The operations runbook uses this output for the release image reference.

Remaining trust: an attacker who can replace both the image and the trusted report, control the builder or control the Docker daemon is outside this content-verification guarantee. No cryptographic signing/identity-provider verification, SLSA level or reproducible-build certification is claimed.

### A-05 — CI exposure and operational acceptance — LOW hardening, partly remediated

All checkouts now disable persisted credentials; workflow permissions remain `contents: read`; all Actions are commit-pinned; jobs have bounded timeouts; no image is published and no real cluster is deployed. Integration still uses only disposable Compose/kind fixtures and the dedicated kubeconfig script. All kind invocations, including teardown, now use an explicitly exported private kubeconfig; port-forward cleanup runs on failure too. A full smoke with an inherited disposable sentinel kubeconfig passed and left that sentinel byte-for-byte unchanged. GitHub branch protection, CODEOWNERS enforcement, organization runner controls, cloud workload identity and production tailnet ACL review require owner-side configuration and were not verified remotely.

Native GCS/Azure account tests, provider staging lifecycle, production CNI/TLS/ACL enforcement, recurring encrypted backups and restore/revocation procedures remain acceptance requirements. These were not fabricated as successful during this audit.

## CI and SBOM outputs

The workflow has independent Rust feature-matrix, shared Linux build/test, security, integration and SBOM jobs. `build-images` archives are retained one day, public count/status `security-reports` summaries 14 days and allowlisted `sbom-materials` 30 days. Raw scanner logs/matches remain local pending approved durable private archival. It can also be dispatched manually. Security failure does not prevent the independent SBOM job from collecting evidence from a successful build.

`cargo xtask generate-sbom` produces:

- `source.cdx.json`, `source.spdx.json`: curated public dependency manifests only; complete Rust and npm test lock graphs.
- `runtime.cdx.json`, `runtime.spdx.json`, `builder.cdx.json`, `builder.spdx.json`: exported images scanned offline by a digest-pinned, socket-free Syft container.
- `native-toolchain.txt`: Rust version and self-contained libc archive/version identity.
- `materials.json`: source revision/tree fingerprint, dirty-tree flag, lockfile hashes, runtime/builder configuration/image/layer/archive digests and SBOM hashes. It is emitted only after all inventories and completeness checks succeed.

The pre-publication audit materials recorded their dirty-worktree state rather than mislabeling that snapshot as a clean release. Regenerate inventories and scans against the committed source for release use. Dependency manifests may lack license text; Cargo deny's license-policy results complement the inventory. File components in CycloneDX are not additional runtime libraries.

## Verification and limitations

Executed commands and current results are recorded in [results](results.md). Raw ignored evidence is under `.work/security-audit/`, `.work/security/` and `.work/sbom/`; none contains real vault content or deployment credentials. Relevant commands:

```sh
scripts/check.sh
scripts/check-features.sh
cargo xtask test-livesync
scripts/test-s3.sh
cargo xtask test-reference-couch
docker build --target tests .
docker build --target build -t obsidian-sync:builder .
docker build -t obsidian-sync:local .
scripts/scan-security.sh
cargo xtask verify-release --image obsidian-sync:local --scan-report .work/sbom/runtime.scan.json
cargo xtask generate-sbom
cargo xtask scan-supply-chain --platform linux/arm64  # currently FAILS; do not hide it
scripts/validate-deployments.sh
scripts/smoke-compose.sh
cargo xtask test-livesync --image obsidian-sync:local
scripts/smoke-kubernetes.sh
```

The GitHub workflow was statically validated with actionlint 1.7.12 and its constituent commands exercised locally; that local validation does not establish a successful remote Actions run. Local execution is arm64; amd64 CI execution, signing, real-provider and production isolation gates remain unverified.
