# SBOM-first scanning: Syft → Grype

All orchestration and validation are Rust (`xtask/`). Syft **generates** the inventory; Grype scans that inventory for vulnerabilities. Neither replaces Cargo audit/deny, npm audit, source/history secret scanning or native patch/reachability review.

## Run

Build the public-source runtime/builder images first, then:

```sh
cargo xtask generate-sbom
cargo xtask scan-sbom --sbom-dir .work/sbom
cargo xtask verify-release --image obsidian-sync:local --scan-report .work/sbom/runtime.scan.json
cargo xtask scan-supply-chain --platform linux/amd64
cargo xtask findings-ledger --platform linux/amd64 --source-revision "$(git rev-parse HEAD)"
```

`generate-sbom` produces native Syft JSON, CycloneDX and SPDX for source/runtime/builder: **nine inventories**, native-toolchain identity and bound materials. CI supplies the original checksum-verified runtime/builder archives; catalog configuration/layers must match those archives. Both CycloneDX and native Syft source inventories must include the entire Cargo/workspace/npm development lock graphs. The source input mount contains only explicit public dependency manifests.

`scan-sbom` refreshes the Grype database in a separate bounded retrieval container, then scans each native Syft SBOM **offline**, without reparsing images. Syft 1.55.0 and Grype 0.121.0 are digest-pinned. Each process has a read-only root, caller UID/GID, dropped capabilities, no-new-privileges, 128 PIDs, two CPUs, 3 GiB memory and a 1536 MiB bounded tmpfs. There is no Docker socket. Analysis gets one read-only SBOM and a read-only DB, plus a separate empty per-invocation output directory: no writable alias to its input or previously published evidence. Host Rust code validates/copies only the expected bounded regular JSON outputs.

DB retrieval must succeed; DB schema/validity/time are checked, with a 72-hour maximum built age and a five-minute future tolerance. Scan/receipt timestamps expire after 24 hours. No automatic DB retrieval is permitted during offline analysis. A fresh retrieval does not prove every upstream advisory feed is current.

Every Grype match blocks, including **Unknown and Negligible**. Matcher-suppression accounting is explicitly enabled; any reported ignored/suppressed match is counted too, not silently dropped by a default ignore rule. No `--only-fixed`, severity threshold, VEX exception or advisory allowlist is used. Missing/empty/unsupported SBOMs, malformed reports, foreign package IDs, stale evidence, tool/schema changes and substituted source/config/layers/hashes fail closed.

## Applicability investigation, not a second image gate

The [2026-10-30 review](security-exploitability.md) records prerequisite analysis and a fixed-input ignored Rust diagnostic for original Go binaries using govulncheck 1.9.0. This is additive binary metadata/symbol investigation, not a scanner fallback, call graph, automatic VEX or finding suppression. Seven of nine subjects lack usable symbols and the overall diagnostic fails; partial presence results cannot clear them. Public advisory retrieval is separate from offline analysis and preserves bounded failed attempts. Grype remains the sole image vulnerability gate, with every finding/error blocking.

## Private dependency baseline

`cargo xtask dependency-baseline --platform linux/amd64` validates existing fresh registry and source/runtime/populated-builder receipts, native SBOMs/reports and the ten bound generated-material files. CI invokes it even when vulnerability scans report findings. It creates only `.work/security/dependency-baseline.json` (0600); existing/symlinked destinations fail. Compact aggregate accounting and streamed pre-write pretty output are capped at 64 MiB, with at most 64 assets; overflow leaves no published partial baseline. These are report bounds, not host-disk quotas.

Each asset retains config/layers, receipt/SBOM/report digests, DB identity/time, severities and suppressed records. Package/advisory grouping preserves every report occurrence/location and never deduplicates away affected assets. Registry and build architectures remain separate; source/build revision/tree/dirty state come from the original materials, not caller-supplied current HEAD. Build archive hashes are retained assertions, not independently rehashed archive bytes. Classification is only `published-fix-needs-review` or `no-published-fix-in-report-needs-review`; all findings stay under investigation with no invented owner, applicability ruling or risk acceptance. Missing/stale/changed/contradictory/foreign evidence fails closed.

The baseline remains private and is not added to public artifact uploads. Its underlying raw evidence still needs an approved durable private archive; a runner-local file is not that archive. No new scan, complete-native-coverage claim, signature or release authorization follows. See the [implementation plan](dependency-image-plan.md) and [results](results.md).

## Supplier rebuild experiment (retired)

The unused local-only `rebuild-tool` command, compiler/test framework and exclusive Go/Git bases are removed. No candidate was adopted by CI; normal pinned Syft/Grype/Gitleaks scans and their containment/verification remain unchanged, including noexec scanner scratch. Historical source/lock/binary/image materials and findings remain private in `.work/tool-rebuild/`; see [results](results.md). Retirement is not advisory remediation, independent acceptance or elimination of Go-based supplier tools.

## Evidence and privacy

- `.work/sbom/NAME.syft.json`, `.cdx.json`, `.spdx.json`: the inventories.
- `.work/sbom/NAME.grype.json`: private raw scanner result.
- `.work/sbom/NAME.scan.json`: unsigned content receipt binding the native SBOM, raw report, tool pins, time, count and image subject.
- `.work/security/sbom-chain/ARCH/`: per-declared-image inventories/reports/receipts, summary and findings ledger.

The content verifier requires the receipt **and adjacent bound native SBOM/raw Grype report** through an approved trusted channel. A replaced report, SBOM or subject fails verification. Its immutable image ID is content binding, not signature verification, builder authenticity, whole-chain approval or permission to deploy.

Only explicitly public source/images and synthetic data may enter these tools. Public CI security artifacts contain allowlisted count/status summaries; raw reports/logs stay local pending an approved protected durable archive. Public SBOM artifacts are separately allowlisted inventories/materials, never arbitrary report directories. Output validation is not general DLP.

## Trivy retired by owner request

Syft → native SBOM → offline Grype is the sole image-scanning path. Trivy's executable pin, special resource profile, legacy report reader/ledger/publication code, comparison commands and `.github/scanner-transition.json` gate are removed. There is no fallback or parallel scanner requirement. The current declared-image inventory has **ten active images**, including Grype itself. The owner replaced kind/kindest-node with k3d; K3s, mandatory k3d-tools and the pause sandbox are explicitly pinned and included. Disabled add-ons/load balancers are not silently pulled. Missing/empty payload catalogs and any findings still fail, never become clean results. Historical kind findings remain retained. The standalone Alpine helper is retired: its daemon-visible source proof, build-context canaries and UID-scoped synthetic cleanup remain, using the already required pinned Rust build base. This does not remove BusyBox/native findings from the builder or turn build/test tooling into a distroless runtime. The two unused experiment-only Go/Git bases are retired, not patched. The owner also retired external reference CouchDB and reused the existing in-process Rust HTTP fixtures instead of introducing another mock server; historical CouchDB image findings are not claimed remediated.

The earlier comparison's **27 baseline-only asset/advisory pairs** remain historical investigation evidence. Retiring the comparison policy is an explicit owner decision, not a claim of scanner equivalence, independent review or advisory remediation. Existing ignored raw baseline/comparison files and historical measurements are not deleted or relabeled clean. Current Grype findings, every reported suppressed match, malformed/missing/stale evidence and scan errors still fail security and Required CI. Initial source/runtime/builder results were **0 / 0 / 19**; see [results](results.md) for exact measured scope.

Grype's cold database occupied about 3.1 GiB on disk in the trial; no tiny-database or general speedup claim is made. Java packages remain cataloged/scanned through the native SBOM without the retired scanner's separate Java DB. Egress sandbox support remains deferred.
