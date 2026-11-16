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

Build/test stages may contain Rust and OS/compiler utilities. The Dockerfile uses BuildKit's built-in frontend, which supports its cache mounts; no separately downloaded custom frontend is required. The daemon remains a trusted external build dependency, not a claimed patched or inventoried application layer. Every declared external image and the populated builder remain subject to their existing gates. The final runtime remains digest-pinned static/distroless/nonroot and adds only `/server`; configuration, credentials and data are mounts.

The candidate builder uses a digest-pinned GNU SDK with a separately fixed Rust 1.99.1 toolchain and Zig 0.17.1-r1 C/C++ compiler. This is not a GNU runtime migration: the build-only Rust adapter forces the native musl Cargo/linker target, rejects conflicting C/C++ targets, and retains the ELF interpreter rejection. Unsupported architectures fail; a registry catalog or clean SDK-base scan does not establish static linkage, DNS behavior, client compatibility or populated-builder cleanliness. Full native qualification is still required before adoption. Compilation targets use fresh disk-backed per-RUN writable BuildKit binds; writes are discarded afterward rather than trusted as shared Cargo artifact state. Registry and content-keyed Zig caches remain. This prevents an older test executable from passing against changed source with older COPY mtimes; no shared cache is globally cleared.

CI transfers checksum-verified archives rather than rebuilding images in downstream jobs. Syft inventories and Grype reports bind the original configuration/layers, source/tree/dirty state, platforms and artifact hashes. A source label or unsigned checksum does not establish builder authenticity.

## Disposable source-built S3 fixture

`cargo xtask test-s3` owns one fixed RustFS 1.0.5 source fixture, not a configurable supplier-build framework. Its private Docker context contains only the reviewed recipe and hash-bound public source/tool inputs. Native GNU Rust 1.100.0 is separate from the application's fixed Rust 1.99.1/static-musl SDK; no compiler/std ABI is mixed. The full upstream default feature set, opt-level 3 and thin LTO remain; code-generation partitioning is explicit. One complete audited build retains the original 2400-second compilation limit; a separate 1200-second runtime-packaging phase performs no Cargo invocation, inside the unchanged 60-minute integration job. The rejected library-only prebuild triggered shadow-rs release-metadata refresh and repeated the expensive graph; it is not retained as a retry or an extra compilation allowance. Compiler target caches are recipe-hash-bound and exclusively locked; the source/compiler/profile inputs cannot share an unqualified cross-recipe artifact cache.

The Rust driver binds actual image IDs/configuration/layers, source revision, recipe bytes, upstream archive and native compiler identity. It generates all three inventory formats for the complete populated fixture builder and actual cargo-auditable runtime, then runs fresh offline zero-finding checks with the unchanged scanner containment. Accepted/suppressed matches cannot qualify this new fixture. Only then does it replace the canonical Compose marker with the exact verified image ID and run the existing storage/client/E2EE/compression/restart controls using new synthetic credentials. No caller-selected image or floating-tag fallback is accepted.

The service remains nonroot with the original disposable memory/tmpfs restrictions. All service-credential creation occurs after scanner qualification; scanners see only public archives, never a socket, operator HOME, real data or service credentials. Runtime/builder tags are task-owned and removed after use; private bound evidence remains. CI uploads only an allowlisted count/hash status, not raw provider logs/reports or newly built service images. This fixture is not a service distribution, production performance qualification, application release or authorization to deploy.

## Our DevSecOps tools

[PRJXAI/devsecops](https://github.com/PRJXAI/devsecops) packages explicit CLI containers. Syft, Grype and Gitleaks use qualified published digests; keep other host tools until their own replacement contracts and inventories pass. Do not substitute those images for the Rust builder, BuildKit/Engine or RustFS service. Live Kubernetes tests and their K3s/k3d/pause assets are retired, not release dependencies.

Adoption requires:

1. A completed tool-specific publish **and provenance** job, not just a successful sibling or a source push.
2. Verified multiarch manifest/platform/config identities and source/workflow-bound provenance.
3. Verified anonymous access: tools are required to be public, without consumer package credentials.
4. Literal digest changes in the actual tool constants, unchanged schema/flags/mount/resource behavior and real seeded detection/inventory controls.
5. Consumer correctness, client, storage and disposable deployment validation. Keep host Cargo audit/deny and npm/source/history checks.

Never put a guessed or placeholder digest in an active pin. Known supplier risks remain visible under the consumer's [exact snapshot policy](security.md); producer acceptance is not automatic consumer authorization.

### Active scanner images

Source **`7d20ea6ba4956a65db1640ec3752534d9dc4b727`** passed fresh exact-source native qualification, separate manual-main publication, provenance and anonymous verification:

| Tool | Published index digest | Release |
|---|---|---|
| Syft | `sha256:5375dc13c75626a7dfec919e11fe075241abd0b0ab3c4cd8d4a13890d73b428a` | [43749937129](https://github.com/PRJXAI/devsecops/actions/runs/43749937129) |
| Grype | `sha256:e9d7ab082648d53929f90761b0e6f70e306814a8711afa85aa6de9c361347d4b` | [43749940786](https://github.com/PRJXAI/devsecops/actions/runs/43749940786) |

Both architectures of each source derivative have **0 findings / 0 ignored / 0 accepted / 0 blocking**. Independent consumer checks verify anonymous index/member/config access, exact native catalog bindings and GitHub provenance restricted to the source SHA, manual-main ref, hosted runners and the tool workflow. Active constants use the published digests and `sha-7d20ea6ba4956a65db1640ec3752534d9dc4b727` tag. CLI flags, mounts and scanner containment remain unchanged. Raw native reports are not normalized or rewritten: validators explicitly admit Syft **1.57.1 / schema 16.1.13** and Grype **0.121.3**, while retaining the exact historical format pair for old evidence. Mixed/unknown version-schema pairs still fail. An initial new-format rejection is retained. Historical rules for the older source remain untouched and do not approve new artifacts; source/runtime/builder and full registry qualification remain consumer gates.

Gitleaks subsequently publishes from merged source **`95c6d9c2dd324d7a6f7ed1ebdaeebe5c9a55ce27`** in manual-main run [43779284917](https://github.com/PRJXAI/devsecops/actions/runs/43779284917): index **`sha256:f9dbb39a13bddc19e7e8a4dbdce8d3e204ebd146eef35340ca2b59cf9636b14b`**. Both fresh native preparations retain **0 findings / ignored / accepted / blocking**, complete original Go/native notices and physical corresponding sources, and the mandatory loader-only exit check. Publication/provenance/anonymous gates pass. Independent consumer checks verify both native catalog/config bindings, exact entrypoints and restricted main/source/workflow attestations without registry credentials. Its active constant uses the actual `sha-95c6...` delivery, not a predicted digest or transferred historical acceptance. Initial independent verification correctly rejects the new package's config redirect until the existing fixed-package allowlist explicitly adds Gitleaks; the same single-hop/digest/no-token-forwarding restrictions and negative tests remain.

**Anonymous access passes for all three packages**; the earlier Syft/Grype access changes remain separately attributed. Index/member/config digests, both native platforms, nonroot/source metadata, producer catalog bindings and exact source/workflow provenance all verify. Earlier HTTP 401/403 failures remain historical; this is not an application-release or hosted Required CI result. `xtask/tests/tool_delivery.rs` contains separate ignored anonymous and explicitly authorized private qualification tests, plus ordinary pin/substitution/risk-migration negatives. Historical applicability subjects retain their original upstream image identities and binary paths.

### Public package access

Existing public packages: [Syft](https://github.com/orgs/PRJXAI/packages/container/package/devsecops%2Fsyft), [Grype](https://github.com/orgs/PRJXAI/packages/container/package/devsecops%2Fgrype) and [Gitleaks](https://github.com/orgs/PRJXAI/packages/container/package/devsecops%2Fgitleaks).

The DevSecOps repository and all three adopted packages are **public**, independently verified; earlier owner visibility changes for Syft/Grype and the new Gitleaks delivery remain separate evidence. Future package names still need **Package settings → Change visibility → Public** once; later versions inherit it. Package administration API scopes are not needed for public consumption.

The anonymous verifier permits one HTTPS config-blob redirect from the exact GHCR package/digest path to `pkg-containers.githubusercontent.com`, with default TLS port, no embedded credentials/fragments, bounded metadata and digest verification. It never forwards the registry bearer token or prints/persists signed URLs. Other redirects still fail. The initial strict 307 rejection is retained as a verifier limitation, not a package-visibility failure.

Security/SBOM jobs now use public pulls, with no package-reader secret/login or private archive workaround. Application publication still logs in for writing only after fresh analysis. Private/missing packages fail rather than silently falling back to upstream tools. The producer checks anonymous index/native/config access after provenance and before delivery-artifact upload. New package names require the same one-time owner visibility setting; later versions inherit it.

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

Rust `build-ci-images` and `load-ci-images` replace inline orchestration: Linux tests, one runtime/builder build, checksum-verified archives, strict tag/config/layer checks and exact public artifact allowlists. `install-deployment-tools` installs only pinned Kustomize to render optional manifest examples. No k3d/kubectl/cluster is required or tested.

Only the publish job receives registry-write/OIDC authority. It loads original archives, performs fresh bound analysis **before registry login**, using anonymously available tool images, then `publish-image` revalidates checkout/source/clean materials/archive/runtime evidence and promotes immutable native bytes without rebuilding. Native manifests are fetched back by digest and config-checked before provenance and the allowlisted result upload. Raw reports/private logs never cross public artifacts.

Application tags include the source SHA, run ID/attempt and `amd64`; consumers must pin the resulting digest. No arm64 application release is claimed. Existing output directories refuse reuse. Interrupted/partial registry pushes can leave bytes/tags: absence of a completed provenance/result handoff means **not delivered**, not guaranteed no registry mutation.

Missing/canceled/skipped/failed producers, scanner errors, missing inventories, unaccepted findings and stale/substituted evidence must prevent publication. The owner's current-stack acceptance is not a temporary green bypass for those failures. The retired pause/K3s/k3d assets are absent from the active graph. The unnecessary remote Dockerfile frontend is also retired rather than downloaded; it is not silently exempted while still in use. Their historical inventory errors/findings are preserved, not waived or called fixed.

Until the publication job and verified digest are recorded in [results](results.md), do not advertise a published application image. A local tag, uploaded build archive or runtime-only clean report is not that result. Real infrastructure deployment requires separate authorization and the [operations runbook](operations.md).

## Maintenance

Keep Cargo.lock, the toolchain, Docker builder and CI synchronized; pin external Actions/images literally. Coordinate scanner pin changes with supported SBOM/DB schemas, exact diagnostics and receipt tests. Generate documentation/config copies with `cargo xtask sync-generated`; review changed source before acknowledging fingerprints.

Public artifacts contain allowlisted summaries/inventories/materials, never raw matches, secrets or provider errors. Preserve failed attempts privately and historical outcomes in Git; do not retimestamp old evidence or present a later successful observation as erasing a failed one.
