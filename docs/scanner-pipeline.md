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

## Local supplier rebuilds (not adopted by CI)

With the owner's local-build authorization:

```sh
# Native platform only; no implicit emulation or publication:
cargo xtask rebuild-tool --tool syft --platform linux/arm64
cargo xtask rebuild-tool --tool grype --platform linux/arm64
cargo xtask rebuild-tool --tool gitleaks --platform linux/arm64
```

Rust fetches exact upstream commits without credential helpers/hooks, records a source archive, and uses digest-pinned Go 1.27.3 plus a pinned Git runtime. Gitleaks gets explicit compression/archive/crypto/system/text module updates; the resulting `go.mod`/`go.sum` and compiled-package list are retained. Dependency retrieval is separate from offline verification/build/tests. Compiler containers have a read-only root, caller UID/GID, dropped capabilities, no socket, two CPUs, 6 GiB memory, 256 PIDs and a 2 GiB executable tmpfs (compiler/test exception only; scanner scratch remains noexec). Compilation sees read-only source/modules and separate output. Upstream tests use a disposable writable source copy, never the compiled source or operator files. Syft's two image fixtures are prepared outside the test container; its disposable Alpine round-trip fixture uses the existing maintained helper pin instead of EOL 3.18. Golden expectations and test cases are not removed or rewritten.

Candidates and the populated compiler are exported, cataloged and scanned by the unchanged pinned scanners. Baselines are scanned on the **same platform and DB**. Selected upstream suites run alongside repository-specific nine-inventory/lock-completeness checks, clean/vulnerable offline Grype controls, or redacted deleted-history/clean-directory secret controls. Builds are serialized; cancellation and timeouts retain cleanup. `.work/tool-rebuild/TOOL-RUN/` retains private source/lock/binary/image materials, test logs, raw reports and `experiment.json`.

These are local experiments, not maintained supplier releases, signatures, reproducible/frozen release builds or reviewed advisory closures. The command exits nonzero for any candidate/compiler match or test failure. A version string is not a trusted image identity. Production tool pins are unchanged; no arbitrary scanner override is exposed to CI. The Go/Git build bases are added to the declared-image inventory rather than hidden. amd64 validation, remaining findings and independent review remain pending. See [results](results.md).

## Evidence and privacy

- `.work/sbom/NAME.syft.json`, `.cdx.json`, `.spdx.json`: the inventories.
- `.work/sbom/NAME.grype.json`: private raw scanner result.
- `.work/sbom/NAME.scan.json`: unsigned content receipt binding the native SBOM, raw report, tool pins, time, count and image subject.
- `.work/security/sbom-chain/ARCH/`: per-declared-image inventories/reports/receipts, summary and findings ledger.

The content verifier requires the receipt **and adjacent bound native SBOM/raw Grype report** through an approved trusted channel. A replaced report, SBOM or subject fails verification. Its immutable image ID is content binding, not signature verification, builder authenticity, whole-chain approval or permission to deploy.

Only explicitly public source/images and synthetic data may enter these tools. Public CI security artifacts contain allowlisted count/status summaries; raw reports/logs stay local pending an approved protected durable archive. Public SBOM artifacts are separately allowlisted inventories/materials, never arbitrary report directories. Output validation is not general DLP.

## Trivy retired by owner request

Syft → native SBOM → offline Grype is the sole image-scanning path. Trivy's executable pin, special resource profile, legacy report reader/ledger/publication code, comparison commands and `.github/scanner-transition.json` gate are removed. There is no fallback or parallel scanner requirement. The current declared-image inventory has **12 active images**, including Grype itself and the two Go/Git bases for local supplier experiments.

The earlier comparison's **27 baseline-only asset/advisory pairs** remain historical investigation evidence. Retiring the comparison policy is an explicit owner decision, not a claim of scanner equivalence, independent review or advisory remediation. Existing ignored raw baseline/comparison files and historical measurements are not deleted or relabeled clean. Current Grype findings, every reported suppressed match, malformed/missing/stale evidence and scan errors still fail security and Required CI. Initial source/runtime/builder results were **0 / 0 / 19**; see [results](results.md) for exact measured scope.

Grype's cold database occupied about 3.1 GiB on disk in the trial; no tiny-database or general speedup claim is made. Java packages remain cataloged/scanned through the native SBOM without the retired scanner's separate Java DB. Egress sandbox support remains deferred.
