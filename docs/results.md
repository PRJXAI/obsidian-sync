# Verification record

This is the measured delivery/operations status, not an implementation diary or release certificate. Earlier audits, retired tools and failed experiments remain in Git and private evidence. Consolidating documentation does not relabel them successful.

## Cleanup implementation — 2026-10-30

Branch `refactor/behavior-preserving-cleanup`; scope and unchanged guarantees are in the [execution contract](cleanup-plan.md#execution-contract).

- Documentation reconciliation: generated/link checks and local deployment rendering pass. Removed the unsupported `/_uuids` claim and contradictory live Kubernetes recommendation; retained historical failed release evidence.
- Transaction readability: expanded job claims/completion/inspection, revision/checkpoint publication and read selection without changing transaction modes, SQL predicates/parameters, authorization order or commits. `cargo test --locked --workspace` passes (**42 application / 66 xtask**, **9 ignored**); `cargo xtask test-livesync` passes all **11** genuine-client scenarios including restart.
- Shared publication: added pre-refactor characterization for request-key boundaries/scoped replays and the public `Engine.db` field; both pass before and after extraction. Private `blob`/`replay` modules now serve Couch/jobs and legacy wrappers without schema/API/hash changes. Workspace tests pass (**44 application / 66 xtask**, **9 ignored**), strict all-target/all-feature Clippy passes, and all **11** native real-client/restart scenarios pass.

- HTTP extraction: added three pre-refactor characterization tests for encoded IDs/ETag/HEAD/If-Match, malformed queries/unsupported roots/mixed bulk rows, and response-drop permit release. The initial permit test used invalid `max_requests=1` and failed fixture configuration; corrected it to the unchanged minimum of two with two held responses, then all **18** Couch tests passed before refactoring. Error/codec, database, document, bulk and changes-feed moves were each followed by all **18** Couch tests and **11** real-client/restart scenarios, all passing. Strict workspace/all-target/all-feature Clippy passes. `http.rs` is reduced from **915 to 363 lines**; helpers remain private and middleware/admission order is unchanged.

## Repository assessment and local sync — 2026-10-30

Reviewed source `e240ab9`; runtime/tooling source and lockfiles were unchanged. The [cleanup plan](cleanup-plan.md) is proposed work, not an implemented refactor. Host: Darwin arm64, Rust **1.99.1**, Node **24.22.1**, npm **11.19.1** (host Node differs from CI's pin).

| Executed command | Result |
|---|---|
| `cargo xtask docs check` (initial) | PASS; no initial link/source-review drift |
| `scripts/check.sh` | PASS: debug/release builds, formatting, strict workspace Clippy, **42 application + 66 xtask tests**; **3 provider + 6 diagnostic tests ignored**; fresh Cargo audit and deny pass |
| `scripts/check-features.sh` | PASS: all **eight** storage-feature cells, including filesystem-only, with debug/release/Clippy/tests and formatting |
| `cargo xtask test-livesync` | PASS: **11** reported genuine Commonlib/PouchDB scenarios against a disposable native filesystem server, including restart |
| `scripts/test-s3.sh` | PASS: explicit S3 storage contract plus the same real-client/restart fixture against disposable loopback RustFS; not native-provider certification |
| `scripts/validate-deployments.sh` | PASS: optional Compose/Kustomize rendering only; no cluster/API operation |
| `docker build --target tests .` | PASS: Linux/musl test stage executed, not merely a cached test result |
| `docker build --target build -t obsidian-sync:builder .`; `docker build -t obsidian-sync:local .` | PASS, with build cache reuse |
| `cargo xtask verify-image` | PASS: static ELF, explicit nonroot identity, only `/server` executable, no shell/package manager |
| `cargo xtask test-livesync --image obsidian-sync:local` | PASS: the same real-client/restart scenarios against the container runtime |
| `scripts/smoke-compose.sh` | PASS: private probes, second-writer denial, graceful stop and subsequent offline administration on persisted storage; the separate client fixture verifies content after a serving restart |
| `cargo xtask generate-sbom`; `cargo xtask scan-sbom --sbom-dir .work/sbom` | PASS: nine inventories and fresh Grype matching; source/runtime **0/0** matches, builder **19 accepted / 0 blocking** |
| `cargo xtask verify-release --image obsidian-sync:local --scan-report .work/sbom/runtime.scan.json` | PASS: bound runtime identity `sha256:baf10f55108f4c910066b71c52c0ecd1d54f3eedda3730987acf4ae36340aef2`; content verification, not publication approval |
| `cargo xtask scan-sources` | PASS: fresh audit/deny, minimized source and independent history secret scans, source-mount check |
| `cargo test --locked -p xtask` (final standalone run) | PASS: **66** tests, **6** explicit diagnostics ignored |
| `cargo xtask sync-generated`; `cargo xtask sync-generated --check`; `cargo xtask docs check`; `scripts/validate-deployments.sh` (documentation handoff) | PASS: generated files unchanged, links/source fingerprints current, optional deployment examples render |

The native, S3 and runtime fixtures exercised Unicode note create/read/update/move/logical-delete, two-peer offline conflicts, concurrent update CAS, paginated replication, a **3 MiB** binary roundtrip, E2EE/compression and randomized encrypted replay, bootstrap recreation, Fast Fetch, live feeds and durable conflicts/checkpoints/encrypted content after restart. Each fixture stopped the server cleanly after the final verification. Post-run checks found no matching server process, fixture container or `livesync-*`/`s3-*`/`compose-*` fixture directory. No existing vault or external provider was accessed.

**Desktop limitation:** this was not initiated inside Obsidian's UI. The installed desktop application was not launched and no existing vault was opened. The tools available here did not provide desktop UI automation; genuine pinned client libraries were used instead. The disposable two-vault desktop test remains pending as described in the cleanup plan. Mobile, Obsidian filesystem watchers and plugin onboarding are not certified by these results.

Warnings retained: deny reported duplicate versions of `hashbrown`, `syn` and `winnow`; npm reported deprecated transitive compatibility-fixture packages and **zero audited vulnerabilities**. No dependency or policy was changed to remove warnings. Local review command logs are ignored files under `.work/repository-review-*-20261030.log`; SBOM/scan materials remain private under `.work/sbom/` and `.work/security/`. Materials identify `e240ab9` with a dirty documentation tree at generation time, not a final clean release revision.

Not rerun for this assessment: full seven-image registry scans/ledger/baseline, hosted Required CI/publication, benchmarks, native AWS/GCS/Azure/MinIO, private TLS/CNI or provider disaster recovery. The broad workspace run intentionally skips credentialed provider/explicit diagnostic tests; S3 was separately exercised above. Live Kubernetes testing remains retired, not a blocked prerequisite. No images were published and no real infrastructure was deployed.

## Current-stack decision — 2026-10-30

The owner accepted the investigated current-stack risks and authorized independent tool-image delivery and consumer integration. The exact policy is [documented here](security.md); all original findings remain counted. This is not an exploit-absence, vulnerability-free or regulated-production claim.

Before acceptance, the retained current inventory measured:

| Subject | Matches / outcome |
|---|---|
| Source / final runtime | **0 / 0** |
| Populated native arm64 builder | **19** |
| Grype / Syft | **23 / 18** per registry architecture |
| Dockerfile frontend / Gitleaks | **23 / 225** |
| K3s / k3d-tools | **123 / 114**, including Critical/High |
| Rust build base / RustFS | **16 / 15** |
| Static runtime base | **0** |
| Pause | **ERROR: empty payload catalog**; no finding count assigned |

Per architecture: **ten declared images, eight finding-bearing, one catalog error, one passing**. Registry measurements are separately attributed amd64/arm64, not native execution qualification. Acceptance changes exact known-match disposition, not these raw counts or inventory-error status. That ten-image baseline could not complete with missing pause coverage. The owner's later retirement of live Kubernetes testing removes its three assets from the active graph, without relabeling these historical findings/errors.

## Verified application behavior

The last full local handoff before this delivery (`e049adc`, preserved applicability investigation) passed:

- `scripts/check.sh`: build/release/fmt/strict workspace Clippy/tests, fresh RustSec audit/deny and documentation checks.
- All **eight** optional-storage feature cells; **59 ordinary xtask tests**, five ignored explicit evaluations/diagnostics.
- Actual Linux/musl Docker **`tests`** target, static/nonroot binary-only runtime and private build-context canaries.
- Native and actual-runtime Commonlib/PouchDB fixtures, E2EE, conflict/tombstone/checkpoint/reset behavior and persistent restart.
- Disposable RustFS/S3 streaming/conditional-create/storage and genuine-client fixtures; npm audit.
- Deployment rendering, source/history secret scans, Compose and required-script **k3d** smoke: private kubeconfig, persistent authenticated identity after pod replacement and second-writer denial.

These are local/synthetic results, not hosted Required CI or native AWS/GCS/Azure/MinIO/GUI/mobile/CNI certification. The k3d CLI's default K3s is explicitly overridden by the pinned stable node. Retired kind results are not evidence for k3d; host-CLI smoke is not packaged producer qualification.

The previous `dbc0733` handoff added exact accounting, receipt-scope tamper checks, bounded documentation retirement, Rust CI archive handoff/manual publication and public-artifact boundaries, with **66 ordinary xtask tests / six ignored diagnostics**. Current scanner adoption/setup documentation is separately validated below; earlier results do not transfer automatically to changed binaries.

## Applicability investigation

Retained registry/builder reports contain **231 unique advisory IDs**, not 231 completed decisions or demonstrated exploits. Primary advisories, actual commands, service prerequisites and binary metadata were reviewed; no end-to-end exploit was attempted/demonstrated and no host setting changed.

A separately installed govulncheck **1.9.0 / Go 1.27.3** inspected nine original Linux arm64 Go binaries in no-network/read-only/resource-bounded containers without executing the subjects. Frontend/Gitleaks supplied **25,877 / 18,966** symbols; seven subjects supplied no usable symbols. The narrower two-subject advisory retrieval retained **293 responses / 993,044 bytes** and yielded **16 / 26 symbol-level advisory IDs**. Binary mode has no call graph; those are not proven exploit paths. Overall diagnostic **fails: incomplete symbol coverage**. No negative VEX or module-level fallback.

Wrong identity-level comparison, missing local image, module-less CNI parsing and the broader query's unchanged **512-advisory cap** refusal remain failed captures. The narrower query does not complete that broader attempt. Owned-container absence was explicitly checked. An initial nonexistent Docker target `test` failed; the real unchanged `tests` target then passed. Initial generated-doc drift failed before review/regeneration.

The actual default host BuildKit was **0.27.1**, below the custom-frontend Seccomp/AppArmor fix **0.31.1**. A malicious-frontend prerequisite/backports were not demonstrated/verified. Private K3s HTTP/2/gRPC availability remains credible conditional exposure. Linux/64-bit trigger mismatches and disabled ordinary Gitleaks archive/HTTP-diagnostics entry points narrow particular prerequisites, not all parser/client/native findings. [Security](security.md) retains the operational assessment.

## Tool-image delivery

[PRJXAI/devsecops](https://github.com/PRJXAI/devsecops) releases tools independently, each with native amd64/arm64 preparation, exact inventories/notices, raw-report-bound accepted/blocking accounting and source-bound publish/provenance gates. Syft/Grype are the first selected deliveries. Gitleaks source/runtime and other tools' inventory/control-plane/compiled-coverage gaps are not waived.

**Both scanners are published**, with successful native amd64/arm64 preparation and provenance at producer source `13edb5277101befe100a435f5ade8da6ea3d40af`:

| Tool | Successful run | Published index digest | Each architecture |
|---|---|---|---|
| Syft | [41099233895](https://github.com/PRJXAI/devsecops/actions/runs/41099233895) | `sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c` | **18 accepted / 0 blocking / 0 suppressed** |
| Grype | [41099238680](https://github.com/PRJXAI/devsecops/actions/runs/41099238680) | `sha256:3079a040326484d0b50ac28c7fc2fb25894a22170e81445ab90c400d091378e0` | **23 accepted / 0 blocking / 0 suppressed** |

Credentialed provenance verification passed for both exact subjects, source/signer digest, repository/reusable workflow/main ref and GitHub-hosted runners. After the owner made both packages public, the opt-in credential-free test **passes**: index and all four native manifest/config digests, source/platform/nonroot metadata, producer catalog bindings and source/workflow provenance verify. The known-public control also passes. Earlier token HTTP 401 failures remain retained. Earlier unclassified/classified access attempts remain retained; no token/body was logged. Package metadata inspection also received 403 for insufficient `read:packages` scope; no visibility/grant was inferred.

The active consumer Syft/Grype pins now use these exact source-bound DevSecOps digests. Operator-authenticated index/native-config/catalog/provenance verification passed, and exact existing findings were reconciled for the verified config identities and binary relocation only. No new advisory, version or occurrence budget was approved. Separate anonymous and authenticated tests remain explicit; hosted package grants are not inferred from operator access.

Security/SBOM jobs now use public images without package-reader credentials or private archive workarounds. Publication withholds write login until fresh analysis finishes. Both seven-image registry gates pass; retired Kubernetes/pause assets are not release dependencies. The application publication path has not delivered an image; successful hosted Required CI and explicit release approval still apply. [Release engineering](releases.md) gives the access contract.

## Current release scope — Kubernetes retired, public tools required

The owner explicitly removed live Kubernetes testing. Its CLI/launcher, cluster implementation and dedicated safety/diagnostic fixtures are retired together; K3s/k3d-tools/pause are no longer executed or scanned as release dependencies. Kustomize examples remain locally rendered. The active image graph has **seven** entries; missing active inventories still block. Application authorization/race/cancellation/restart/writer-fencing, genuine-client, storage and Compose coverage remains.

The owner also requires public DevSecOps source and packages. GitHub confirms `PRJXAI/devsecops` is **PUBLIC** with repository ADMIN access, but package administration is separately unavailable: the existing OAuth token lacks package scopes and listing returns HTTP 403. The owner subsequently changed both package settings to Public. Fresh anonymous checks now pass for both, including all four native config bindings and source/workflow provenance; prior 401/403 attempts remain failed historical captures. The agent did not mutate visibility or infer it from authenticated access. Consumer read-token/login and private archive-export paths are removed; images must work publicly. Thus the old local arm64 private-export failure is historical, not a current transport requirement.

Producer publication now requires anonymous index/native-manifest/config verification after provenance and before delivery-artifact upload. It uses a private credential-free config with an explicit empty GHCR auth entry (disabling native keychain auto-discovery) and fixed system buildx discovery paths and strips inherited credentials/proxies. New package names still need one-time owner UI action; repository visibility or a successful private push alone does not establish public availability.

Validation of this scope:

- **PASS:** pinned fresh audit/deny, debug/release, all **eight** feature cells, **65 ordinary xtask tests / six ignored diagnostics**, strict workspace/all-target/all-feature Clippy, actionlint **1.7.12**, generated/link/review checks and local manifest rendering.
- **PASS:** Linux/musl tests and rebuilt runtime/builder, build-context privacy, minimized source/history secret checks, native and runtime Commonlib/PouchDB/restart fixtures, disposable S3 contracts/clients and Compose writer-fencing/restart smoke. No Kubernetes operation or host-context probe was run.
- **PASS:** fresh bound source/runtime matching **0/0**, native builder **19 accepted / 0 blocking**, runtime content verification; source attribution is `b026257` plus a dirty tree, not a clean release.
- **FAIL, retained then corrected:** the first disposable S3 contract saw startup **503** during bucket setup. The existing read-only readiness probe had accepted any HTTP status. It now waits for unauthenticated **403** within the same bound; a bounded synthetic **503→403** test and the unchanged real S3/client contracts pass. No write retry, authorization bypass or contract removal was introduced. Initial strict Clippy failures (unused retired helper, singleton installer loop, synthetic read length) remain retained.
- **PASS after visibility change:** both seven-image registry scans complete: **320 total / 320 accepted / 0 blocking** matches per architecture, six accepted-risk assets and one clean static base. The earlier container-DNS failures remain retained; no host/Docker DNS setting was changed. Registry scans are not native execution or a newly verified application release. Fresh complete baseline/hosted Required CI remain separate.
- **PASS:** anonymous package verification now covers both index/member/config digests, four native bindings and exact provenance. The initial verifier rejected GHCR's HTTP **307** blob response; a bounded, fixed HTTPS CDN hop now works without forwarding Authorization or logging signed URLs. Negative host/scheme/port/credential/fragment/path/size cases and **66 ordinary xtask tests / six ignored diagnostics**, plus strict all-target/all-feature Clippy, pass. Earlier 401/403 and 307 attempts remain retained.

Producer checks pass **133 ordinary tests / 39 ignored diagnostics**, strict Clippy and fresh dependency audit. Its explicit anonymous positive control verifies a public index, native manifest and parsed config; the new publisher gate has not completed a real publication. The previous consumer hosted run [41123422579](https://github.com/PRJXAI/obsidian-sync/actions/runs/41123422579) failed its SBOM job and Required CI; publication did not run. At that earlier run, public packages and fresh Required CI were still prerequisites. Public access was subsequently verified as recorded above; a successful fresh Required CI and application image release are not claimed here. Previous measurements remain attributed to their older scope.

## Previous scanner integration validation — b026257

- **PASS:** `scripts/check.sh` with pinned Cargo audit **0.22.2** and fresh audit/deny data; all **eight** feature cells; **71 ordinary xtask tests / seven ignored explicit diagnostics**; strict workspace/all-target/all-feature Clippy; actionlint **1.7.12**; generated/link/source-review checks. An earlier check also passed with host audit 0.22.1 before the pinned rerun; it is not the pinned result.
- **PASS:** actual Linux/musl `tests` target and fresh runtime/builder builds; build-context privacy canaries; deployment rendering and minimized source/history secret scans.
- **PASS:** native Commonlib/PouchDB, disposable RustFS/S3 and actual-runtime client/restart fixtures; npm audit reports zero vulnerabilities. Local client fixtures use host Node **24.22.1**, distinct from CI's pinned Node **26.13.0**. One earlier runtime-client attempt failed before client output; a later rebuilt-image attempt passed. The initial failure remains retained without an established cause.
- **PASS:** optional Compose smoke and required-script disposable k3d smoke using dedicated checksum-verified kubectl **1.37.2**, pinned host k3d/Kustomize, private configuration, writer fencing and persistent identity. These validate examples, not mandatory application dependencies or real-cluster/CNI approval.
- **PASS:** fresh DevSecOps Syft inventories and Grype matching: source/runtime **0/0**, populated native arm64 builder **19 accepted / 0 blocking**; bound runtime content verification. Local source attribution is `dbc0733` plus a dirty working tree, not a clean release handoff.
- **PARTIAL registry gate:** amd64 catalogs/scans accept the exact known Syft **18** / Grype **23** matches; all nine non-pause assets complete. Pause remains an empty-inventory error. Arm64 additionally fails to export both private scanner assets from the local daemon: native pulls report cached success, but retained export evidence contains manifest references without their config/layer members; explicit-platform export refuses that incomplete target. No empty catalog is scanned or counted clean. Authenticated all-four live catalog qualification remains failed; prior metadata/provenance qualification does not complete it.
- **FAIL, retained:** anonymous scanner access (both HTTP 401); initial private registry cataloging without host-mediated auth; initial manifest/config daemon-identity mismatch; strict Clippy test-module placement; initial builder recipe digest prefix mismatch (**19 blocking**) before normalization to the unchanged exact raw policy digest. New/changed findings and changed recipes still fail; no acceptance budget was expanded to fix these checks.
- **Procedure deviation:** a host `kubectl --client` metadata probe unexpectedly invoked its credential dispatcher and reported expired authentication. No cluster operation was requested. Subsequent Kubernetes validation used only the required isolated script and dedicated binary; setup guidance now forbids operator-client probes even with `--client`. No credential/context/daemon modification or cache/evidence deletion was used to force success.

The previous hosted consumer run [41106161649](https://github.com/PRJXAI/obsidian-sync/actions/runs/41106161649) passed build, Rust matrix, SBOM and disposable integration jobs, but security/Required CI failed and publication was skipped. This is not a successful hosted release. Fresh hosted access/Required CI for the adopted pins remains separate; no application publication is claimed. A complete ledger/baseline still cannot pass with missing pause/private-archive coverage. Benchmark, native cloud/provider/GUI/mobile and important-data deployment qualification were not performed.

New [native-first onboarding](getting-started.md), [configuration](configuration.md) and [LLM setup](setup-with-ai.md) guidance separates the minimal executable/TOML/local-storage requirements from optional Compose/Kustomize examples. Approval gates, private human-only key entry, reset/current-UUID/key rotation and backup requirements are documented, not claimed as an unattended live GUI setup.

## Remaining operational qualifications

- Fresh complete source/runtime/builder/registry baseline and hosted Required CI for the final source. Public scanner access and both seven-image registry gates now pass. Pause/K3s/k3d are retired scope, not active blockers or missing-inventory exemptions.
- Protected source/release authority, accountable approval and verified publication/package visibility.
- Durable private raw-evidence archive and hard host/provider-staging quotas; finite report/archive caps are not those quotas.
- Provider-native IAM/conditional-write/lifecycle, private TLS/CNI egress enforcement, matched encrypted restore/revocation drills and managed credential custody.
- Privacy-safe durable security auditing, crypto/retention/erasure policy and deployment-specific regulated-use approval.

No benchmark rerun, host/daemon upgrade, production deployment, real-vault data access, provider-storage/cluster operation or new GUI/native-provider certification occurred. The unexpected credential-dispatcher metadata-probe deviation is recorded above. See [operations](operations.md) for runbooks and [security](security.md) for the control register rather than historical task counts.
