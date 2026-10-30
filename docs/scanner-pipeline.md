# SBOM-first scanning: Syft → Grype

Syft **catalogs**; Grype matches the native inventory offline. Rust (`xtask/`) orchestrates/validates them. Neither replaces fresh Cargo audit/deny, npm audit, source/history secret checks or native/source applicability work. There is no Trivy fallback or second image-scanner requirement.

## Run

Build public-source runtime/builder images first; see [releases](releases.md).

```sh
cargo xtask generate-sbom
cargo xtask scan-sbom --sbom-dir .work/sbom
cargo xtask verify-release --image obsidian-sync:local --scan-report .work/sbom/runtime.scan.json
cargo xtask scan-supply-chain --platform linux/amd64
cargo xtask findings-ledger --platform linux/amd64 --source-revision "$(git rev-parse HEAD)"
cargo xtask dependency-baseline --platform linux/amd64
```

`generate-sbom` emits native JSON, CycloneDX and SPDX for source/runtime/builder: **nine inventories**, native-toolchain identity and bound materials. CI supplies original checksum-verified archives; catalogs must match their configuration/layers. Native/CDX source inventories include the full Cargo/workspace/npm **development** lock graphs. The source mount contains only explicit public manifests, not a workspace/credential dump.

## Retrieval and containment

A separate bounded container refreshes Grype's DB. Analysis has no network or automatic updates and reads one exact native SBOM and a read-only DB. Supported tool/schema versions remain explicit; changing an image pin does not permit arbitrary schema changes.

Each scanner uses read-only root, caller UID/GID, dropped capabilities, no-new-privileges, 128 PIDs, two CPUs, 3 GiB memory and 1536 MiB tmpfs. No socket/operator HOME. Declared registry images are cataloged anonymously, including the DevSecOps scanners. Public packages are required: no consumer read token, Docker credential mount or private native-export workaround is used. Source/runtime/builder archives retain offline cataloging and their original binding checks. Private/missing assets, invalid inventories and mismatched identities still block. Output is a distinct empty per-invocation directory, not a writable alias of input/prior evidence. Host Rust validates/copies only bounded regular expected JSON. Captures/deadlines/cancellation and checked owned-container cleanup remain mandatory.

DB retrieval must succeed. Validate schema/status/time: **72 hours** maximum built age, five-minute future tolerance; receipts/reports expire after **24 hours**. A successful retrieval is not proof every upstream feed is current. The cold database occupied about **3.1 GiB** in trials; report/archive caps are not whole-host/cache quotas.

## Findings and exact acceptance

Enable matcher-suppression accounting. Count every effective and ignored match, including Unknown/Negligible; retain raw fields and diagnostics. No `--only-fixed`, severity filter, generic VEX or automatic ignore.

The owner accepted a fixed investigated stack snapshot on **2026-10-30**, including known fixable findings. After catalog/report validation, `risk.rs` compares exact subject/platform or builder recipe, package/version/type/location, advisory/namespace/severity/fix/related identities and occurrence limits against `accepted-risks.json`. Receipts record the policy and total/accepted/blocking counts; verification recomputes them instead of trusting a claimed acceptance. Status is **accepted-risk**, not fixed or clean.

**Unaccepted/new matches still fail. Runtime/source findings cannot inherit registry/builder acceptance.** Missing/empty/unsupported inventories, scan errors, unknown diagnostics, malformed reports, foreign packages, stale/substituted source/config/layers/hashes and extra occurrences remain failures. Do not regenerate acceptance from a failing scan; [security](security.md) defines the owner decision and residual risks.

## Declared assets and coverage

The active inventory contains **seven** images: Syft, Grype, Gitleaks, static runtime base, Rust build base, Dockerfile frontend and RustFS. Live Kubernetes testing is retired by owner request; K3s/k3d-tools/pause are not executed, installed or release inputs. Their old findings and pause inventory error remain historical, not fixed or accepted as missing coverage. Any empty active catalog still fails before Grype. Registry cataloging is not native functional qualification.

Active Syft/Grype pins use the source-13edb52 published [DevSecOps images](https://github.com/PRJXAI/devsecops), after authenticated index/native-config/catalog/provenance verification. CI now requires [public package access](releases.md#public-package-access), with no reader-token fallback. Repository and both scanner packages are verified public. Anonymous index/member/config digest and source/workflow provenance checks pass after the owner's visibility changes. Registry scans of all seven assets now complete on both architectures with exact accepted-risk accounting; this is not native application qualification or publication. Exact existing scanner risks were reconciled only for verified config identities and the binary-path relocation; no new finding budget was granted. Schemas, containment and seeded detection controls are unchanged. Keep compiler/daemon/node/service identities and host Cargo audit/deny separate.

Retired kind/helper/reference-CouchDB/experimental rebuild/comparison assets and their failed findings remain historical evidence, not remediated code. Helper source visibility/context-canary/UID-scoped cleanup duties still run using the pinned build base. In-process real-router fixtures are not independent Apache CouchDB certification.

## Private baseline and trusted evidence

`dependency-baseline` validates fresh registry and source/runtime/populated-builder receipts, native inventories/reports and ten bound generated-material files. It creates only `.work/security/dependency-baseline.json` (0600), refuses existing/symlink destinations and enforces **64 MiB / 64 assets** with streamed pre-write bounds and no partial publication on overflow.

Retain every occurrence/location, suppression, DB/time/config/layer/report/SBOM/receipt identity and accepted-risk decision. Preserve original source/tree/dirty/platform attribution; do not substitute caller HEAD or merge registry/native-build architectures. Archive hashes retained in materials are assertions unless original bytes are independently rehashed. Published-fix/no-fix grouping is not an applicability ruling. Missing/stale/contradictory/foreign input fails; a narrower partial diagnostic cannot complete a failed baseline.

Evidence layout:

- `.work/sbom/NAME.{syft,cdx,spdx}.json`: inventories; `materials.json` and `native-toolchain.txt`: bindings.
- `.work/sbom/NAME.grype.json`: private raw matches; `NAME.scan.json`: unsigned content receipt.
- `.work/security/sbom-chain/ARCH/`: per-image inventories/reports/receipts, summary and ledger.

Content verification requires the receipt **and adjacent bound native SBOM/raw report** through an approved trusted channel. Its immutable image ID establishes content binding, not signature/builder authenticity, whole-chain approval or deployment permission. Runtime verification still receives **all raw matches** and refuses any runtime finding.

Only public/synthetic inputs. Public artifacts are allowlisted summaries or separately allowlisted inventories/materials, never raw report directories. Raw evidence needs an approved durable private archive; runner-local files do not provide one. Output validation is not DLP.

## Additive binary investigation

The fixed-input ignored `go_symbols` Rust diagnostic uses govulncheck 1.9.0 to inspect original Linux arm64 binaries without running them. Separate bounded public advisory retrieval precedes offline analysis. Seven of nine subjects lack usable symbols; the overall result intentionally fails. The two partial symbol outputs compute no call graph and prove neither exploit reachability nor absence. No scanner fallback, automatic VEX, filtering or approval follows. See [security](security.md) and [verification](results.md).
