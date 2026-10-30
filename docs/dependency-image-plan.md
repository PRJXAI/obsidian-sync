# Dependency and consumer-image remediation plan

## Objective and scope

Make the dependencies and images used by `obsidian-sync` eligible for the existing security gates, without losing client coverage or hiding findings. This is the detailed M2 execution plan under the [security remediation plan](security-remediation-plan.md), not release approval or an implementation-complete checklist.

Two repositories participate:

- **devsecops:** package and qualify the scanner executables, their embedded dependencies and runtime closure. Tools remain independently releasable, each with native amd64 and arm64 evidence.
- **obsidian-sync:** qualify the actual builder, frontend, helper, S3 service, Kubernetes node and runtime; later integrate only verified scanner releases. Tool containers are not replacements for whole runner jobs, compilers, daemons or services.

This planning change authorizes no publication, consumer pin replacement, risk-policy exception, maintained supplier fork, host/daemon modification or real deployment. Role ownership below is proposed; actual accountable reviewers still need naming. Regulated-production controls outside M2 remain separate.

## Evidence baseline

Recorded evidence is from 2026-10-29; refresh it before selecting replacements. Counts are match records, not distinct advisories or future acceptance thresholds.

- Consumer source `391c0db`, [run 40905080579](https://github.com/PRJXAI/obsidian-sync/actions/runs/40905080579): application/Linux tests, eight feature cells, SBOM generation and real-client/S3/disposable deployments pass. Security rejects **19 populated-builder matches** and **8/9 declared images**, with zero scan errors. Source/runtime vulnerability and current-source/history secret summaries are zero.
- Producer source `f6625c8`, [run 40905121732](https://github.com/PRJXAI/devsecops/actions/runs/40905121732): Gitleaks production preparation passes on both architectures with **1 accepted / 0 blocking**. Syft/Grype retain **18 / 23 blocking findings per architecture**; six other tools retain contract/inventory blockers. Nothing was published.
- The separate local amd64 **registry** scan below is not native amd64 execution. The populated local arm64 builder has **43** matches; do not substitute that for hosted amd64's 19 or the unpopulated builder base's 16.

| Consumer asset | Current pinned version / source location | Local amd64 registry matches | Work package |
|---|---|---:|---|
| Syft | 1.55.0; `xtask/src/sbom.rs` | 18 | D1 |
| Grype | 0.121.0; `xtask/src/grype.rs` | 23 | D2 |
| Upstream Gitleaks image | digest-pinned supplier image; `xtask/src/security.rs` | 225 | D3 |
| Rust builder base | 1.99.1-alpine3.24; `Dockerfile` | 16 | I1 |
| Dockerfile frontend | 1.28.0; `Dockerfile` | 23 | I2 |
| Alpine helper | 3.23.7; `xtask/src/security.rs` | 3 | I3 |
| RustFS | digest-pinned supplier image; `docker-compose.test-s3.yml` | 66 | I4 |
| Kubernetes node | 1.37.0; `xtask/src/deployment.rs` | 864 | I5 |
| Static runtime base | pinned Chainguard static; `Dockerfile` | 0 | I6 |

This table is the original nine-image baseline, not current pin state. The 2026-10-30 owner-authorized refresh removes the standalone Alpine image by reusing the required Rust build base, updates base digests and selects released RustFS 1.0.4; that refresh initially yielded eight images. The subsequent owner-directed kind→k3d migration replaces the node with explicitly pinned K3s/tools/pause dependencies, yielding ten current images without waiving missing inventories/findings. Literal current digests remain in source and bound evidence, not duplicated into a second pin catalog. New images must also be inventoried/scanned; inventory cardinality is not a permanent cap.

Two rejected alternatives remain evidence:

- RustFS 1.0.4: **15 matches per registry architecture**. Its minimal arm64 prototype passes storage/client tests but Syft catalogs only three base packages, omitting RustFS/crates. Inventory fails; findings remain null, not zero.
- Debian Gitleaks native-runtime prototype: **26 blocking findings plus the existing accepted finding**, incomplete closure/review and no native amd64 execution. It is not an approved replacement.

Exact measurements and limitations: [results](results.md). Producer technical detail: [supplier remediation](https://github.com/PRJXAI/devsecops/blob/main/docs/supplier-remediation.md) and [release blockers](https://github.com/PRJXAI/devsecops/blob/main/docs/release-blockers.md).

## Non-negotiable acceptance rules

1. Consumer policy remains **zero reported findings**, including suppressed, Unknown and Negligible. Producer Gitleaks acceptance does not propagate to consumers or other tools. Empty fix arrays, unreachable-symbol claims and upstream `wont-fix` labels do not authorize exceptions.
2. Keep Grype as the sole image vulnerability scanner and Syft as cataloger. Preserve host Cargo audit/deny, npm audit and source/history secret checks. No fallback scanner, fixed-only filter, severity threshold, broad VEX waiver or arbitrary engine override.
3. An empty or base-only catalog is not clean. Verify main executables, embedded Go/Rust dependencies, native libraries and relevant build flags. Do not fill UNKNOWN versions from CLI strings, rename modules to evade matching or edit raw SBOMs to match expected tuples.
4. Prefer maintained released artifacts. A source derivative must have fixed source/patch/compiler/dependency inputs, artifact-specific notices/source/provenance and a defined maintenance owner before adoption. No generic supplier-rebuild framework.
5. All first-party orchestration/tests stay Rust: producer's existing driver and consumer `xtask`. Keep bounded resources/captures, separate retrieval/offline work, read-only inputs, no scanner socket, private logs, deadlines, cancellation and checked cleanup. Record existing host-disk-quota gaps; do not claim caps solve them.
6. Do not remove tests, required components or assets merely to obtain green. Preserve LiveSync revisions/conflicts/tombstones/checkpoints, streaming integrity, persistent writer exclusion and all real-client scenarios. Final server image stays static/distroless/nonroot with only `/server` added.
7. Qualification uses exact bytes on **native linux/amd64 and linux/arm64** for any image claimed to support both. Registry scans and emulation do not replace execution. Consumer's currently amd64 hosted gate is not evidence of arm64 support.

## Implementation checkpoint — 2026-10-29

The private P0 aggregation is implemented as `cargo xtask dependency-baseline`, including a CI security step and bounded create-only output. It has been exercised against nine registry images plus source/runtime/populated-builder captures, preserving the latter's original dirty-tree source identity and arm64 versus registry amd64 scope. This is baseline assembly, not closure of inventory/provenance/archival gaps.

The separate producer Syft arm64 experiments measure **18 → 4 → 1 blocking finding** after Go 1.27.3 and a frozen go-jose 4.1.6/x/net 0.62.0 manifest patch. Production remains unchanged: upstream tests failed/incomplete, compiler catalog output exceeded its cap, the patched full run was interrupted and only a separately labeled retained-binary scan completed. Native amd64 and source/notices/provenance are unapproved; Syft does not inherit Gitleaks's exception.

RustFS supplier assets now yield 1,151 Cargo.lock component records and archive-subject/source assertions, but no component hashes/dependency relationships or established per-platform executable/native binding; no binary inventory approval follows. That initial investigation found no newer kind node. The owner subsequently replaced the fixture with k3d 5.9.0 / stable K3s 1.37.1 and explicitly inventoried tools/pause images; current scan results, not the old node totals, govern acceptance. Builder triage identifies libcurl 8.23.0-r0 fix targets alongside unresolved BusyBox/binutils/Perl records; an uncached same-recipe builder probe timed out and produced no qualified probe image/scan. Subsequent normal builds and fresh arm64 scans on 2026-10-30 report source/runtime/builder **0 / 0 / 19**, with libcurl 8.23.0-r0 present; the original probe failure and older 43-match capture are preserved. Exact outcomes and blocked gates are in [results](results.md). All remaining work packages below stay open until their acceptance criteria pass.

## Work packages

Every package produces a small reviewed change, immutable candidate identities, complete evidence or an explicit blocker. An experiment that reduces counts is not completion. Do not wait on one supplier before investigating independent assets.

### P0 — Freeze the asset and finding baseline

**Proposed owner:** supply-chain engineering; AppSec reviews classification.

- Preserve latest hosted summaries and retained raw local captures before any refresh. Use the existing scan/ledger flow, not another reporting framework.
- For each platform record source SHA/dirty state, index and selected manifest/config/layers, archive/SBOM/report hashes, tool pins, DB schema/build time and scan time. Group findings by package/advisory while retaining every asset/location/suppressed record.
- Classify each group: fix available; maintained replacement; source change needed; no fix/alternative demonstrated; or inventory/provenance unknown. Verify current fixed versions and aliases rather than extrapolating old totals.
- Separate unpopulated base, populated build/test stages, final runtime and transient remediation compilers. Account for native/static dependencies and dependencies that do not appear in an OS package database.
- Record host-installed Cargo/Go/Node tools, Docker/BuildKit/runtime versions, Actions and npm lock inputs as additional trust dependencies. Nine image scans alone do not cover the whole runner. Inspect only permitted public/non-secret identities; no host changes follow.
- Resolve an owner-approved private archive for raw evidence; until then preserve it locally and explicitly retain the archival blocker. Publish only allowlisted summaries/materials.

**Exit:** per-asset prioritized ledger, fix-target/source identities and reproducible evidence references; no findings disappear through regrouping. Missing hosted detail must be obtained through an approved private path or reproduced with a clearly labeled new artifact, not invented from summaries.

### D1 — Syft embedded compiler and dependencies

**Proposed owner:** devsecops/tool maintainer.

1. Recheck maintained releases and literal native artifact hashes. The last inspection found no release newer than the already pinned 1.55.0; a distroless base refresh cannot replace embedded Go code.
2. Map actual binary modules/imports against current matches. Select a patched supported Go compiler covering current stdlib findings, with pinned compiler image/source identity. Previously inspected Go 1.26.10/1.27.3 are candidates to revalidate, not automatic current fix guarantees.
3. Prefer a fixed upstream release; otherwise propose one explicit Syft source derivative. Preserve release build tags, version/format behavior, inputs and dependency locks. Record before/after manifests and binary metadata.
4. Investigate the x/crypto all-version OpenPGP match separately. A compiler update cannot fix it; removing an import does not help if the affected module remains embedded for another package. Any genuine dependency replacement needs maintained code, license review and unchanged behavior, not a renamed fork.
5. Collect corresponding module/native notices and source provenance. Recapture unchanged native inventories rather than reusing the supplier profile for a derivative.

**Acceptance:** source/archive/registry input contracts, JSON/SPDX/CycloneDX outputs, Cargo/workspace/npm development coverage, no missing executable/module/native identities, and fresh complete scans on both architectures. Compare semantic inventories to the baseline; do not require byte-identical reports with different IDs/timestamps.

### D2 — Grype compiler, legacy Docker module and scanner qualification

**Proposed owner:** devsecops/tool maintainer; AppSec reviews matching behavior.

1. Apply the same release/compiler/x/crypto process as D1; no Syft/Gitleaks risk rule is inherited.
2. Migrate release-source Docker imports in `cmd/grype/cli/commands/completion.go` to reviewed maintained split Moby modules. Adapt filter/options/result APIs and close client resources; an import-only replacement is insufficient.
3. Replace the legacy `pkg/homedir` test dependency in `internal/format/writer_test.go` while preserving path/writer tests. Check the entire direct/transitive graph and final executable for the old root module; adding split modules alongside it is not removal.
4. Preserve completion's tagged/dangling filtering, prefix behavior, multiple tags and unavailable-daemon fallback. Use synthetic/mock endpoint tests, not the operator daemon. Retain existing upstream checks; classify environment-required integration cases rather than dropping failures.
5. Qualify DB retrieval separately from offline matching. Test real seeded vulnerable/clean inputs, every severity and suppression, malformed/missing/foreign SBOMs, stale/future DBs, no-network analysis, error exits, diagnostics, timeouts and cleanup.

**Acceptance:** complete native catalogs, module-removal evidence, preserved CLI/detection/error behavior and fresh scans. A newer Grype must not become acceptable simply because it reports fewer findings; account for every changed match and schema/DB/matcher change.

**Scanner bootstrap:** keep current pinned engines for bounded public/synthetic measurements until replacements are qualified. Compare old/new outputs against a common compatible fresh DB and identical inventories, plus seeded controls; investigate differences. If no common supported DB/schema exists, record the incompatibility and qualify an explicit migration with the seeded corpus; do not coerce or downgrade schemas. Known scanner findings remain visible and are not a bootstrap waiver. Self-scanning is not independent trust/provenance. After qualification, update producer engine pins, exact invocation/diagnostic bindings and receipt expectations in one reviewed change; qualify again under the selected engines. Consumer pin/schema validation is a later separate change, never a caller-supplied override.

### D3 — Gitleaks dependency and Git/native closure

**Proposed owner:** devsecops/tool maintainer; source/legal and runtime owners review separately.

- Preserve the already tested fixed Gitleaks source/patch/Go compiler, offline race suite, upgraded inventory and byte-checked Go notices. Do not restore the old supplier inventory or repeat a compiler-only experiment as new remediation.
- Compare the consumer's 225-match supplier image to an actual new candidate, not arithmetic subtraction. Complete source/native closure for the existing Git/runtime or evaluate a supported alternative that clears its own gates. The rejected Debian candidate is not the default fallback.
- Keep exact Git/glibc overlays, selected-file ownership, notices, source delivery/relinking and provenance on the dossier. Obtain missing authenticated bytes, not merely similar upstream patches.
- The retained loader-only exit failure needs separately authorized disposable-host/runtime comparison or scoped tracing. No daemon update/restart, longer deadline, dropped clean-HEAD control or retry-to-success is part of this plan.

**Acceptance:** unchanged source/deleted/bare/all-ref/clean-HEAD/redaction/archive controls and complete native closure, fresh two-architecture evidence, resolved runtime failure and accountable source review. A producer release with the existing single accepted risk is still **ineligible under consumer zero-findings policy**. Either a genuine zero-finding maintained solution is qualified or a separately approved consumer-policy proposal is required; do not silently choose the latter.

### I1 — Rust builder base and populated build/test stages

**Proposed owner:** consumer build/toolchain maintainer.

1. Triage the exact populated-builder findings, not just the Rust base. Inspect currently required `musl-dev`, CMake, Make, Perl, Clang/LLD, binutils and Git and their installed dependency closure. Keep registry base and populated-stage findings separate.
2. Prefer a maintained Rust/OS patch combination with reviewed binary/source identities. Keep `rust-toolchain.toml`, CI and Docker toolchain aligned; inspect actual libc/static archives and compiler provenance.
3. Remove an installed package only after proving it has no required build/test/inspection caller. Do not move a vulnerable required compiler into an unscanned stage, delete package databases/caches to hide attribution, or assume an OS-family switch is safer.
4. If no supplier combination qualifies, propose a narrowly pinned builder recipe with explicit package/source inputs and an update owner. Scan all newly introduced bases and acquisition/populated stages. Record external C/assembly: self-contained musl, SQLite, AWS-LC and other enabled native dependencies.
5. Rebuild all eight feature cells and Linux test target. Preserve ELF interpreter rejection and unchanged final static/nonroot image; generate inventories/materials from the actual populated images and final executable.

**Acceptance:** qualifying base and populated build/test inventories/scans on supported native architectures, exact toolchain/native identities, full tests and archive/config/layer binding. A clean final runtime alone cannot close the builder failure.

### I2 — Dockerfile frontend, separately from the daemon

**Proposed owner:** consumer build/platform maintainer.

- Trace findings to the exact frontend executable, embedded Go/modules and any pseudo-version patch ancestry. Prefer a verified patched upstream frontend; otherwise propose a focused source build with pinned compiler/dependencies and maintenance ownership.
- Preserve required syntax: cache mounts, build/test targets, `.dockerignore` handling, multi-stage COPY, source-revision labels and image export behavior. Rerun included/excluded-input canaries and the real Linux/runtime builds with the candidate.
- Keep frontend, BuildKit daemon, Docker Engine, containerd and runc identities separate. A frontend/CLI image fix does not patch the running daemon. Host remediation requires a separate authorized platform plan.

**Acceptance:** zero-finding complete frontend inventory, compatible real builds and source/provenance/notices. Do not remove the frontend pin to move a known asset into an unpinned builtin implementation.

### I3 — Helper image, preserving its real duties

**Proposed owner:** consumer tooling maintainer.

- Inventory all three uses: daemon-visible nonempty-source check, build-context include/exclude assertions and synthetic-data cleanup under container UID permissions.
- Implemented under the 2026-10-30 owner instruction: retire the standalone Alpine image and reuse the already required digest-pinned Rust build base for these build/test-only utility duties. No new helper binary/image, shell program or runtime payload is introduced. Its BusyBox/native findings still belong to I1, not an exception.
- Preserve nonzero failures for absent/empty source, excluded-file checks, symlink/path boundaries, UID permissions, cancellation and teardown. Never replace the daemon-visible mount proof with a host-only existence check.

**Acceptance:** no standalone helper dependency, all source/build-context/privacy/cleanup regressions, and the reused builder's normal I1 scan/qualification gates. The distroless runtime remains unchanged in shape. Never delete safety checks or run scanners as root merely to avoid them.

### I4 — RustFS payload inventory before repackaging

**Proposed owner:** consumer storage-fixture maintainer; supplier/source reviewer.

1. Request or locate an artifact-bound supplier SBOM/build provenance covering the actual Rust executable, Cargo features/locks and vendored native code on both architectures. Image labels and a source Cargo.lock alone do not authenticate what was compiled.
2. If supplier evidence is insufficient, propose a fixed-source auditable RustFS build with a pinned toolchain/lock/features and verified embedded dependency metadata. Validate that the pinned Syft cataloger actually recovers the payload graph, including native dependencies via separately reviewed evidence where necessary.
3. Preserve raw Syft output unchanged. Any supplemental source/native evidence must state its origin/coverage and be cryptographically bound to the executable/build; define and test its validation before relying on it. Never inject guessed tuples into the SBOM.
4. Only then evaluate minimal static packaging with complete runtime/source/notices. The existing prototype's functional pass is useful but its missing-payload failure remains a required negative control.
5. If neither supplier evidence nor a maintainable source build qualifies, review a maintained S3-compatible alternative against the same real service contract; no fake in-process store or reduced tests.

**Acceptance:** full payload/native inventory and fresh zero-finding scans, then conditional-create races, 8 MiB streaming/hash/size integrity, Commonlib/PouchDB E2EE/compression/reset/conflict/checkpoint/restart tests, nonroot/read-only/credential handling and checked teardown on native architectures. This qualifies a disposable S3 fixture, not AWS/GCS/Azure/MinIO certification.

### I5 — Kubernetes node: early feasibility review, not late surprise

**Proposed owner:** consumer disposable-deployment/platform maintainer.

- Start inventory triage alongside D1/D2 because the node has the largest recorded match count. Identify OS packages, Kubernetes components, etcd, containerd/runc, CNI, snapshotters and helper binaries with their source/toolchain identities.
- Evaluate a maintained supported Kubernetes patch/node release compatible with the selected k3d version. Patch/rebuild only against an explicit maintained source and update strategy if a released node cannot qualify; changing Kubernetes versions requires compatibility review.
- Do not strip required node components, package attribution or scans to reduce totals. Review any genuine unused component removal individually against the supported fixture, retaining its source/binary evidence.
- Execute consumer Kubernetes tests **only through `scripts/smoke-kubernetes.sh`**, with its disposable kubeconfig/cluster and unchanged teardown, readiness, second-writer denial and PVC restart checks. No current context, real cluster or unverified claim of CNI/NetworkPolicy enforcement.

**Acceptance:** complete node/runtime/component inventory, qualifying scans and the unchanged native disposable lifecycle. A devsecops k3d or Docker **CLI** release cannot close node findings. If supported node distributions cannot meet zero findings, raise that feasibility blocker immediately rather than replacing Kubernetes coverage with a skipped job.

### I6 — Runtime base and first-party dependencies

**Proposed owner:** consumer server/dependency maintainer.

- Retain the current zero-match static base unless fresh source/signature/provenance/CA review or new advisories justify a change. Zero OS matches does not establish embedded server native coverage.
- Keep Cargo.lock committed; patch first-party Cargo/native dependencies one compatible change at a time, with fresh advisory data and license checks. Inspect feature/target graphs and avoid workspace feature unification masking tooling usage.
- Preserve locked Commonlib/PouchDB/npm test graphs, install-script restrictions and audit. Client upgrades require protocol/E2EE/restart requalification, not merely a clean npm audit.
- Add no runtime shell, config, secret, scanner or helper. Retain streaming/SQLite/revision invariants and the actual static executable checks.

**Acceptance:** fresh source/runtime scans, complete Cargo/npm/native materials and existing correctness/security/client tests. No data/schema/retention migration is included here.

## Sequencing and integration checkpoints

| Checkpoint | Parallel work | Required output before advancing |
|---|---|---|
| C0 — Baseline | P0; identify owner/review/archival decisions | Bound ledger and candidate/fix identities; explicit unknowns |
| C1 — Feasibility | D1/D2 source graphs; I1 builder; I4 metadata; I5 node; I2/I3 supplier options; D3 source/runtime dossier | One reviewed primary route per asset, or a concrete no-fix/source/authorization blocker |
| C2 — Small candidate changes | Separate Syft compiler/dependency step, Grype migration, builder/helper/frontend changes; RustFS only after inventory route works | Fixed-input patch/recipe, regression results and measured before/after inventories/scans; no adoption yet |
| C3 — Native qualification | Per-asset amd64/arm64 work; reviews can proceed in parallel | Complete payload/native coverage, zero consumer-eligible findings, source/notices/provenance dossier and all required controls |
| C4 — Producer release handoff | Qualified tools release independently; infrastructure images follow their own reviewed release path | Fresh tool/source-bound handoffs, actual archive-load checks, approvals and successful approved publication/attestation; verify visibility and anonymous pull where claimed |
| C5 — Consumer integration | One verified pin change at a time; preserve host tooling until replacement coverage is proven | Exact manifest/platform digests and provenance checked; schema/receipt tests updated narrowly; complete consumer workflow passes |

Do not wait for all nine devsecops tools to adopt a qualified scanner. The other six CLI inventory/contract work packages remain under the producer's release-blocker plan; incomplete cargo-deny must not replace the host gate. Conversely, scanner readiness does not waive any consumer infrastructure asset.

C4/C5 are the later release/delivery handoff, not permission to execute it now. The consumer has no approved general publication workflow for new builder/helper/service/node images: define the smallest explicit protected path, repository, source/lock ownership, native evidence, digest/attestation verification and approval before using a custom image there. Do not force services into the existing CLI-only release contract or push them ad hoc. A verified supplier release can use the separately reviewed supplier-adoption path.

**First implementation increment:** complete P0 and submit a fixed-input Syft compiler/dependency candidate, while independently investigating the builder's exact populated findings and RustFS/node feasibility. Next integrate Grype's legacy-module migration as its own change. Do not start with a broad base-image bump, another unqualified minimal repackaging or a new framework. Upstream fixes, source availability and explicit policy/runtime decisions determine the eventual critical path; there is no defensible calendar delivery date yet.

## Common verification and definition of done

For every candidate retain old/new source and image identities, lock/module graphs, actual compiler/build flags, full SBOMs, all finding/suppression counts, source/notices, failed attempts and exact functional results. Use the [scanner freshness and schema contract](scanner-pipeline.md); freshness must be re-established at final handoff, not borrowed from a historical replay. Gate missing executables, truncated/foreign inventories, symlinks/oversized inputs, stale/wrong-source/config/platform receipts, cancellation, output overflow, timeouts and failed cleanup.

Consumer final validation uses the same immutable rebuilt/exported artifacts throughout:

- `scripts/check.sh`, `scripts/check-features.sh`, fresh `cargo audit` and `cargo deny check`;
- Linux/musl Docker test target, runtime filesystem/ELF checks and exact archive/config/layer binding;
- native and final-image Commonlib/PouchDB fixtures, `scripts/test-s3.sh`, deployment rendering, Compose smoke and `scripts/smoke-kubernetes.sh`;
- source/history secret checks, complete source/runtime/populated-builder SBOM generation and offline Grype scans, declared-image scans and bound findings ledger;
- Rust tooling unit/negative tests, build-context/input/output privacy canaries, generated files and documentation checks;
- existing benchmark checks where build/native/dependency changes could affect performance, on an otherwise idle machine, with no unmeasured improvement claims.

This workstream is complete only when all consumed assets have the required coverage, fixes and reviews and the actual consumer **Required CI** passes with no missing/skipped/canceled producers. A green scanner job, zero runtime OS findings, lower totals, or successful local prototype is insufficient. All nine producer releases being green is a separate broader goal. Production rollout, compliance acceptance and real-provider/GUI/mobile validation remain separate claims.

## Decision and escalation register

- **No-fix consumer findings:** retain zero-findings by default. If maintained replacements preserving contracts cannot meet it, present exact artifact/package/advisory/fix/alternative evidence and impact. Only the owner/AppSec can choose a separate narrowly bound accepted-risk policy proposal or continued blocking. No automatic policy inheritance or promise that all findings will reach zero.
- **Source derivatives/custom infrastructure:** name a maintenance/security-update owner, approve supported source lines and redistribution/provenance/source delivery, and define an authorized publication path before adoption. Upstream contributions/vendor requests may help but external contact or issue creation is not implied by writing this plan.
- **Native runners and runtime investigation:** confirm isolated native amd64/arm64 capacity. Loader/daemon tracing, privileged comparisons, host changes and packaged k3d control-plane qualification need their separately scoped authorization; existing consumer disposable smoke scope is unchanged.
- **Evidence retention:** approve private raw-evidence storage, access and retention; do not upload raw captures to public Actions artifacts to fill this gap.
- **Review stop:** after the first released option and one narrowly scoped source/repackaging feasibility route for an asset, review its blockers before expanding into a maintained fork or another OS/service. Record concrete missing inputs and tests, not repeated count-only experiments. Never extend a runtime deadline or retry away a failure to claim qualification.

Planning and approvals are separate: none of these decisions is satisfied by a checked experiment, this document, or an assistant's assertion.
