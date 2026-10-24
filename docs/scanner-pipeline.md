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
cargo xtask check-scanner-transition
```

`generate-sbom` produces native Syft JSON, CycloneDX and SPDX for source/runtime/builder: **nine inventories**, native-toolchain identity and bound materials. CI supplies the original checksum-verified runtime/builder archives; catalog configuration/layers must match those archives. Both CycloneDX and native Syft source inventories must include the entire Cargo/workspace/npm development lock graphs. The source input mount contains only explicit public dependency manifests.

`scan-sbom` refreshes the Grype database in a separate bounded retrieval container, then scans each native Syft SBOM **offline**, without reparsing images. Syft 1.55.0 and Grype 0.121.0 are digest-pinned. Each process has a read-only root, caller UID/GID, dropped capabilities, no-new-privileges, 128 PIDs, two CPUs, 3 GiB memory and a 1536 MiB bounded tmpfs. There is no Docker socket. Analysis gets one read-only SBOM and a read-only DB, plus a separate empty per-invocation output directory: no writable alias to its input or previously published evidence. Host Rust code validates/copies only the expected bounded regular JSON outputs.

DB retrieval must succeed; DB schema/validity/time are checked, with a 72-hour maximum built age and a five-minute future tolerance. Scan/receipt timestamps expire after 24 hours. No automatic DB retrieval is permitted during offline analysis. A fresh retrieval does not prove every upstream advisory feed is current.

Every Grype match blocks, including **Unknown and Negligible**. Matcher-suppression accounting is explicitly enabled; any reported ignored/suppressed match is counted too, not silently dropped by a default ignore rule. No `--only-fixed`, severity threshold, VEX exception or advisory allowlist is used. Missing/empty/unsupported SBOMs, malformed reports, foreign package IDs, stale evidence, tool/schema changes and substituted source/config/layers/hashes fail closed.

## Evidence and privacy

- `.work/sbom/NAME.syft.json`, `.cdx.json`, `.spdx.json`: the inventories.
- `.work/sbom/NAME.grype.json`: private raw scanner result.
- `.work/sbom/NAME.scan.json`: unsigned content receipt binding the native SBOM, raw report, tool pins, time, count and image subject.
- `.work/security/sbom-chain/ARCH/`: per-declared-image inventories/reports/receipts, summary and findings ledger.

The content verifier requires the receipt **and adjacent bound native SBOM/raw Grype report** through an approved trusted channel. A replaced report, SBOM or subject fails verification. Its immutable image ID is content binding, not signature verification, builder authenticity, whole-chain approval or permission to deploy.

Only explicitly public source/images and synthetic data may enter these tools. Public CI security artifacts contain allowlisted count/status summaries; raw reports/logs stay local pending an approved protected durable archive. Public SBOM artifacts are separately allowlisted inventories/materials, never arbitrary report directories. Output validation is not general DLP.

## Transition is not an advisory waiver

The default CI path uses Syft → Grype, **not Trivy execution**. Explicit `cargo xtask compare-trivy` / `compare-trivy-supply-chain --platform ...` commands retain the previous scanner for controlled comparison. Its pinned image remains in the declared/comparison inventory until retirement is reviewed; the current inventory therefore has **11 images**, including Grype itself.

```sh
# Requires existing fresh local Trivy baseline reports for the same platform:
cargo xtask compare-scanner-baseline --platform linux/amd64
```

The comparison binds identical image configurations, includes Grype advisory aliases and reports baseline-only IDs as **under investigation**. It is not a claim of equivalence or exploitability. `.github/scanner-transition.json` is fail-closed: unresolved pairs and missing reviewed closure evidence reject `check-scanner-transition`, which CI requires. Changing scanners cannot make those findings disappear or authorize a clean release.

The initial comparison retained **27 baseline-only asset/advisory pairs**. Initial source/runtime scans returned zero Grype matches; the populated builder returned **19** (one Critical, six High, twelve Medium). All 11 image scans completed, with matches in ten. These are scanner associations requiring platform/version/backport/function review, not proof that all are exploitable. No finding was waived. See [results](results.md) for measured scope and [remediation plan](security-remediation-plan.md) for acceptance blockers.

Grype's cold database occupied about 3.1 GiB on disk in this trial; this is not a tiny/no-database scanner. It avoids the separate ~943 MiB compressed Java DB download that overflowed Trivy's small scratch volume. The retained Trivy comparison profile has bounded 5 GiB memory/3 GiB scratch for that cold path; Java scanning is not disabled. No general speedup or regulated-production acceptance is claimed. Egress sandbox support remains deferred.
