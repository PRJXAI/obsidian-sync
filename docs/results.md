# Verification record

This is the measured delivery/operations status, not an implementation diary or release certificate. Earlier audits, retired tools and failed experiments remain in Git and private evidence. Consolidating documentation does not relabel them successful.

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

Per architecture: **ten declared images, eight finding-bearing, one catalog error, one passing**. Registry measurements are separately attributed amd64/arm64, not native execution qualification. Acceptance changes exact known-match disposition, not these raw counts or inventory-error status. A newly complete dependency baseline cannot be produced while pause coverage is missing.

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

Credentialed provenance verification passed for both exact subjects, source/signer digest, repository/reusable workflow/main ref and GitHub-hosted runners. The opt-in credential-free test passes the known-public registry control but **fails with token HTTP 401 for both candidates**. Earlier unclassified/classified access attempts remain retained; no token/body was logged. Package metadata inspection also received 403 for insufficient `read:packages` scope; no visibility/grant was inferred.

The active consumer Syft/Grype pins now use these exact source-bound DevSecOps digests. Operator-authenticated index/native-config/catalog/provenance verification passed, and exact existing findings were reconciled for the verified config identities and binary relocation only. No new advisory, version or occurrence budget was approved. Separate anonymous and authenticated tests remain explicit; hosted package grants are not inferred from operator access.

Security/SBOM jobs request package-read authority and authenticate on the host. Private asset cataloging uses digest-bound native pulls and verified offline archives without mounting credentials into scanners; daemon/manifest/config identities remain distinct. Publication still withholds its write login until fresh scans finish, using a separately supplied read-only tool token if needed. Package visibility/Actions grants remain owner settings. The application publication path has not delivered an image; pause coverage and all Required CI gates still apply. [Release engineering](releases.md) gives the access contract.

## Current integration validation — 2026-10-30

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

- Pause source/native payload inventory; fresh full scan/baseline/Required CI after actual tool adoption.
- Protected source/release authority, accountable approval and verified publication/package visibility.
- Durable private raw-evidence archive and hard host/provider-staging quotas; finite report/archive caps are not those quotas.
- Provider-native IAM/conditional-write/lifecycle, private TLS/CNI egress enforcement, matched encrypted restore/revocation drills and managed credential custody.
- Privacy-safe durable security auditing, crypto/retention/erasure policy and deployment-specific regulated-use approval.

No benchmark rerun, host/daemon upgrade, production deployment, real-vault data access, provider-storage/cluster operation or new GUI/native-provider certification occurred. The unexpected credential-dispatcher metadata-probe deviation is recorded above. See [operations](operations.md) for runbooks and [security](security.md) for the control register rather than historical task counts.
