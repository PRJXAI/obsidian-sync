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

The current delivery adds exact acceptance accounting, receipt-scope tamper checks, bounded documentation-batch retirement, Rust CI archive handoff/manual publication and public-artifact boundaries. **66 ordinary xtask tests / six ignored explicit diagnostics** and strict workspace/all-target/all-feature Clippy pass at the tooling handoff; final checks remain separately recorded below. Prior results do not transfer automatically to changed binaries.

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

The real candidates and verification are staged in `xtask/tests/tool_delivery.rs`; **active supplier pins remain unchanged** to avoid breaking consumer CI. Owner package visibility/explicit Actions read access must be resolved before activation and exact consumer-profile refresh. The manual application publication path is implemented but has not run or published an application image; pause coverage and all Required CI gates still apply. [Release engineering](releases.md) gives the contract and access action.

## Current delivery validation

- **PASS:** `scripts/check.sh` (fresh Cargo audit/deny, debug/release, formatting, strict workspace Clippy/tests and current docs/generated checks); **66 ordinary xtask tests / six ignored explicit diagnostics**; additional strict all-feature/all-target Clippy; actionlint **1.7.12**.
- **PASS:** deployment rendering, build-context membership/private-JSON canaries and fresh minimized source/history secret scans.
- **PASS:** both independent producer native amd64/arm64 release/provenance runs and credentialed cryptographic verification above.
- **FAIL, retained:** opt-in anonymous delivery verification—public control succeeds; both candidate token endpoints return 401. Active pins are not switched and no package access is assumed.
- **Not rerun locally:** the full eight-cell feature loop, Linux image rebuild, fresh all-image SBOM/matching/baseline, genuine client/S3 and Compose/k3d smokes or benchmark. The shared host reports **100% utilization / about 1.1 GiB available**, below even another cold Grype DB (~3.1 GiB). No evidence/cache deletion, disk-limit increase or host/daemon change was used to force them through. Previous local full-suite results remain explicitly attributed above; fresh consumer CI must qualify changed tooling/archives.

The new CI build/load/publish path is covered by Rust boundary tests but has not yet completed a hosted consumer run. No application publication or successful new Required CI is claimed; known pause coverage remains a distinct blocker.

## Remaining operational qualifications

- Pause source/native payload inventory; fresh full scan/baseline/Required CI after actual tool adoption.
- Protected source/release authority, accountable approval and verified publication/package visibility.
- Durable private raw-evidence archive and hard host/provider-staging quotas; finite report/archive caps are not those quotas.
- Provider-native IAM/conditional-write/lifecycle, private TLS/CNI egress enforcement, matched encrypted restore/revocation drills and managed credential custody.
- Privacy-safe durable security auditing, crypto/retention/erasure policy and deployment-specific regulated-use approval.

No benchmark rerun, host/daemon upgrade, production deployment, real-vault/provider/cluster access or new GUI/native-provider certification occurred in this delivery. See [operations](operations.md) for runbooks and [security](security.md) for the control register rather than historical task counts.
