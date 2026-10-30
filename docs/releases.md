# Build and release engineering

## Artifact flow

```text
reviewed source → Linux build/tests → immutable runtime + builder archives
                                      ├─ real clients / S3 / disposable deployments
                                      ├─ source/runtime/builder SBOMs + materials
                                      └─ fresh security checks + explicit risk accounting
                                                     ↓
                                            Required CI / release approval
```

Build/test stages may contain Rust and OS/compiler utilities. The final runtime remains digest-pinned static/distroless/nonroot and adds only `/server`; configuration, credentials and data are mounts.

CI transfers checksum-verified archives rather than rebuilding images in downstream jobs. Syft inventories and Grype reports bind the original configuration/layers, source/tree/dirty state, platforms and artifact hashes. A source label or unsigned checksum does not establish builder authenticity.

## Our DevSecOps tools

[PRJXAI/devsecops](https://github.com/PRJXAI/devsecops) packages explicit CLI containers. Start adoption with qualified published Syft/Grype digests; keep other host tools until their replacement contracts and inventories pass. Do not substitute those images for the Rust builder, BuildKit/Engine, K3s node/tools/pause or RustFS service.

Adoption requires:

1. A completed tool-specific publish **and provenance** job, not just a successful sibling or a source push.
2. Verified multiarch manifest/platform/config identities and source/workflow-bound provenance.
3. Verified anonymous access for public packages, or separately authorized private package access.
4. Literal digest changes in the actual tool constants, unchanged schema/flags/mount/resource behavior and real seeded detection/inventory controls.
5. Consumer correctness, client, storage and disposable deployment validation. Keep host Cargo audit/deny and npm/source/history checks.

Never put a guessed or placeholder digest in an active pin. Known supplier risks remain visible under the consumer's [exact snapshot policy](security.md); producer acceptance is not automatic consumer authorization.

### Published candidates

Source **`13edb5277101befe100a435f5ade8da6ea3d40af`** passed both native architectures, independent publication and provenance:

| Tool | Published index digest | Release |
|---|---|---|
| Syft | `sha256:7d484d97e289e8ba108ef17a7ecd9dbbbe457398b92f5f3d79219a6445aaaf2c` | [41099233895](https://github.com/PRJXAI/devsecops/actions/runs/41099233895) |
| Grype | `sha256:3079a040326484d0b50ac28c7fc2fb25894a22170e81445ab90c400d091378e0` | [41099238680](https://github.com/PRJXAI/devsecops/actions/runs/41099238680) |

Credentialed `gh attestation verify` checks succeeded for the exact subject, source/signer digest, main ref, reusable workflow and GitHub-hosted runners. **Anonymous token access returns 401 for both**, while the known-public registry control passes. These are real published candidates, not active consumer replacements: existing working supplier pins stay unchanged until access is qualified.

An organization owner must make the packages public, or explicitly grant this repository Actions read access and configure/verify least-privilege package login. Repository visibility alone does neither. `xtask/tests/tool_delivery.rs` stages the real immutable candidates and opt-in anonymous/index/native-config/provenance checks; its failed access attempts remain private. No automatic scanner fallback or pin override is introduced.

## Build and validate locally

```sh
docker build --target tests .
docker build --target build -t obsidian-sync:builder .
docker build --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" -t obsidian-sync:local .
cargo xtask verify-image
cargo xtask scan-sources
cargo xtask generate-sbom
cargo xtask scan-sbom --sbom-dir .work/sbom
cargo xtask scan-supply-chain --platform linux/amd64
cargo xtask verify-release --image obsidian-sync:local --scan-report .work/sbom/runtime.scan.json
cargo xtask test-livesync --image obsidian-sync:local
```

Registry scans for another architecture are not native execution. Use `linux/arm64` for a separately attributed arm64 registry measurement. A two-architecture support claim requires actual native qualification of both images.

`verify-release` verifies runtime content through a trusted evidence channel; it does not sign, approve deployment or waive the entire supply chain. Runtime findings remain blocking. Its stdout image ID is safe to use only after the command succeeds. Keep index, manifest, configuration and daemon identity levels distinct.

## Publication contract

Image publication is explicitly authorized work, not automatic deployment. The workflow now provides a **manual main-only Linux amd64** publish path, downstream of successful Required CI. Dispatch inputs `publish` and `redistribution_reviewed` default false; the latter confirms application-specific notices/source arrangements, not merely scanner-tool approval.

Rust `build-ci-images` and `load-ci-images` replace inline orchestration: Linux tests, one runtime/builder build, checksum-verified archives, strict tag/config/layer checks and exact public artifact allowlists. `install-deployment-tools` preserves the pinned host Kustomize/k3d gates; it does not substitute incomplete container replacements.

Only the publish job receives registry-write/OIDC authority. It loads original archives, performs fresh bound analysis **before registry login**, then `publish-image` revalidates checkout/source/clean materials/archive/runtime evidence and promotes immutable native bytes without rebuilding. Native manifests are fetched back by digest and config-checked before provenance and the allowlisted result upload. Raw reports/private logs never cross public artifacts.

Application tags include the source SHA, run ID/attempt and `amd64`; consumers must pin the resulting digest. No arm64 application release is claimed. Existing output directories refuse reuse. Interrupted/partial registry pushes can leave bytes/tags: absence of a completed provenance/result handoff means **not delivered**, not guaranteed no registry mutation.

Missing/canceled/skipped/failed producers, scanner errors, missing inventories, unaccepted findings and stale/substituted evidence must prevent publication. The owner's current-stack acceptance is not a temporary green bypass for those failures. The pause inventory error remains a distinct unresolved gate until valid coverage exists.

Until the publication job and verified digest are recorded in [results](results.md), do not advertise a published application image. A local tag, uploaded build archive or runtime-only clean report is not that result. Real infrastructure deployment requires separate authorization and the [operations runbook](operations.md).

## Maintenance

Keep Cargo.lock, the toolchain, Docker builder and CI synchronized; pin external Actions/images literally. Coordinate scanner pin changes with supported SBOM/DB schemas, exact diagnostics and receipt tests. Generate documentation/config copies with `cargo xtask sync-generated`; review changed source before acknowledging fingerprints.

Public artifacts contain allowlisted summaries/inventories/materials, never raw matches, secrets or provider errors. Preserve failed attempts privately and historical outcomes in Git; do not retimestamp old evidence or present a later successful observation as erasing a failed one.
