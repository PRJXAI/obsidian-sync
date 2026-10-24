# Security remediation plan

**Status: proposed, not executed. Regulated-production acceptance remains blocked.**

This plan covers findings A-01–A-05 in the [security audit](security-audit.md) and R-01–R-09 in the [regulated/exfiltration assessment](regulated-security-assessment.md). It separates already implemented protections, technical remediation, source/binary applicability investigation, deployment validation and policy decisions. Passing the existing tests is a baseline, not closure of the remaining findings.

No repository protection, production configuration, cloud account, vault, retention policy or image publication is authorized by this document. Such changes require explicit owner approval. All initial validation uses synthetic data and disposable infrastructure.

## Implementation boundaries

Preserve the pinned LiveSync/PouchDB contract, revision trees/conflicts/tombstones/checkpoints, scoped replay and persistent single-writer authority. Keep BlobStorage's bounded streaming, vault-generated keys, exact hash/size verification and durable create-only publication across every adapter. Write changed guarantees before concurrent mutation work; add negative authorization, race, cancellation and restart tests. No first-party unsafe Rust, no extra runtime executable, no secrets/config baked into image layers, no unbounded blocking/tasks, no multi-writer/NFS/HPA shortcut, no MCP expansion and no final-data GC without a separately approved protocol-aware retention design. Keep all eight feature combinations and real upstream-client fixtures.

## Closure rules

Each finding gets an owner, applicable asset/digest/platform, evidence, acceptance test and independent reviewer. Allowed dispositions:

- **Remediated:** a reviewed implementation or supplier fix is deployed in the approved scope and its acceptance tests pass.
- **Not affected / not applicable:** exact binary/platform/configuration or approved workload-policy evidence establishes applicability; security/compliance owners approve the decision and its review/expiry conditions.
- **Open / under investigation:** still blocks acceptance. A missing report, UNKNOWN, expired evidence, skipped/canceled check or scan error is not a pass.
- **Risk accepted:** remains explicitly identified as residual risk; it is not mislabeled fixed or used to silently turn the current gate green.

Raw scanner reports must remain available. No blanket allowlists, severity reductions, `ignore-unfixed`, fake version labels or removed tests. A future evidence/VEX-aware acceptance gate would itself require an explicitly approved policy change, schema/signature validation and negative tests. Until then, the current fail-on-findings gate remains unchanged. If policy requires literally zero raw findings, retain that requirement and replace/rebuild dependencies or improve validated attribution rather than suppress results.

## Milestones and ownership

| Milestone | Priority / findings | Accountable roles | Exit condition |
|---|---|---|---|
| M0. Scope and enforce source controls | P0; R-02, A-05 | Owner, AppSec, compliance | Approved workload/control profile; protected source/release rules verified with denied-operation tests |
| M1. Contain CI inputs, outputs and runners | P0; R-01, R-05 | CI/platform, AppSec | Synthetic input-leakage and runner-isolation tests pass; no regulated data or production authority in public CI |
| M2. Resolve the seven images and native dependencies | P0; A-02, A-03, R-05 | Supply-chain/AppSec, component maintainers | Complete, fresh, artifact-bound findings have approved closure; no unresolved applicable vulnerabilities |
| M3. Authorize and attest releases | P0; A-04, R-04 | Release/platform, AppSec | Fail-closed promotion/admission verifies source, all required gates, provenance, signatures, digest and approval |
| M4. Restrict network, identity and storage authority | P0 before real data; R-03, R-06, R-08 | Platform/network, storage, identity | Positive/negative tests prove approved paths, provider permissions and device/access controls for the selected deployment |
| M5. Add security auditing and export detection | P0 before real data; R-06, R-07 | Server engineering, AppSec, security operations | Durable privacy-safe events, bounded failure behavior, tested collection and actionable alerts |
| M6. Approve crypto, retention and recovery | P0 before real data; R-08, R-09 | Compliance/legal, cryptography, storage/operations | Required crypto/retention decisions and authorized recovery/rotation evidence accepted |
| M7. Independent acceptance and operation | Final gate; all | Independent reviewer and owner | Evidence matrix complete, exceptions explicit, operational procedures exercised; written scope-limited approval |

M0 and CI containment start first. M2 and the designs for M4–M6 can proceed in parallel once scope is defined. M3 cannot authorize promotion until M0–M2 requirements are satisfied. No customer-data rollout occurs before M4–M7. Work can proceed on remediation branches while main/release checks remain blocking; do not create a temporary green security bypass to avoid that dependency.

## M0 — Define requirements and protect the source

1. Record data classes, jurisdictions, tenancy/compartments, deployment/storage provider, residency, required framework, retention/erasure/hold rules, RTO/RPO, crypto/FIPS requirements and approval authority. Choose an initial supported profile, such as one isolated filesystem installation; do not imply native-cloud acceptance from compilation.
2. Agree named organizational reviewer teams and break-glass procedure. Add reviewed ownership for workflow, Dockerfile, dependency locks, deployment, authentication, storage and retention changes. Do not invent or hardcode personal identities in the repository.
3. With explicit permission, enable GitHub rules for main and release refs: PR review, stale-approval dismissal as required, restricted bypass, no routine force push/deletion, and all required checks. Require a stable aggregate check that fails if any matrix/build/security/integration/SBOM requirement is failed, missing, canceled or unexpectedly skipped.
4. Restrict Actions to approved pinned publishers/commits; retain read-only default tokens and disabled persisted checkout credentials. Keep write/OIDC permissions out of untrusted PR jobs.
5. Define how any emergency bypass is independently approved, logged, time-bounded and reviewed; it must not make an unresolved finding disappear.

**Acceptance:** denied direct/force pushes and unapproved sensitive-file changes are demonstrated in an authorized disposable repository or approved test branch; a red/missing/canceled security result prevents promotion. Repository settings are exported as non-secret evidence. No real main policy is modified without owner permission.

## M1 — Complete CI containment

Already implemented: caller UID/GID for Trivy, dropped capabilities/no-new-privileges, scanner socket isolation, offline Syft/Gitleaks, curated source inputs, independent bare history mirror, and ignored-file/detached-HEAD canary regressions. Keep these controls and their tests.

Remaining work:

- Run untrusted PR/build/test workloads only on clean ephemeral runners with no production credentials, customer data, tailnet access, real kubeconfig or trusted organizational network routes. Do not reuse privileged kind hosts for regulated workloads.
- Separate controlled dependency/advisory retrieval from offline analysis/build phases where supported. Use approved registries/mirrors and allowlisted retrieval destinations; do not claim network-disabled tools also prevent output disclosure.
- Inventory every mount and output channel. Add resource/time bounds where missing, minimal read-only inputs and independent cache/report directories. Avoid passing host environment/credential files into tools.
- Introduce a reviewed output-publication policy: report schema/size checks, redaction/secret checks and explicit artifact allowlists. Public CI handles only public source and synthetic data. Output validation is defense in depth, not proof that a compromised tool cannot encode data; classified inputs belong in an approved private processing boundary with controlled release of results.
- Add synthetic checks for excluded input paths, symlinks, source/history coverage, denied networking, report/log leakage, oversized output, timeout cleanup and missing/tampered reports. Validate that useful scanner failures remain observable without exposing input content.

**Acceptance:** no unintended mounts or production authority; controlled negative tests show canaries absent from scanner inputs/published outputs and ordinary outbound traffic denied for offline tools. No real sensitive data or external exfiltration endpoint is used. Actual secret-bearing Git inputs retain an appropriately protected reporting path.

## M2 — Supplier images, binaries and native code

Create an artifact-specific findings ledger: image and config/layer digest, architecture, source revision, executable/library path, advisory, fixed version/commit, feature/call-path conditions, current use, evidence, reviewer and status. Deduplicate package associations without discarding affected assets.

| Work item | Remediation path | Required verification |
|---|---|---|
| SC-01 Syft | Prefer a patched stable supplier image; otherwise build reviewed pinned source with an approved patched Go toolchain/base. Remove/replace unsupported crypto dependencies where necessary rather than assuming a Go upgrade fixes them. | Offline source/runtime/builder SPDX/CycloneDX generation, full Rust/npm development-lock coverage, material/hash binding and output isolation |
| SC-02 Trivy | Patch/rebuild approved stable source/base and relevant Go dependencies. Resolve Brotli/musl applicability and obsolete OpenPGP dependency use. Do not adopt canary only because one severity disappears. | Fresh DB retrieval, real local/archive/registry scans, all severities/UNKNOWN visible, complete-report and failure-injection tests |
| SC-03 Gitleaks | Use maintained patched source/runtime and archive dependencies. Verify 32-bit-only and unused-network-path claims against actual binaries/platforms. Preserve history coverage and redaction. | Seeded synthetic-secret detection/redaction, bare/detached/all-ref history, ignored-input isolation and archive resource-bound tests |
| SC-04 frontend and daemon | Treat Dockerfile frontend, BuildKit daemon and Docker/container runtime as distinct assets. Verify patch ancestry/binary provenance for pseudo-version matches; patch the actual executing component. Restrict approved frontend provenance, not merely digest syntax. | Trusted builder/daemon inventory, source/binary evidence, sandbox/entitlement/config checks and verified test/runtime builds |
| SC-05 kind/node | Obtain or build maintained Kubernetes/container-runtime/node images; review helper binaries and enabled runtimes/snapshotters. Do not remove the disposable Kubernetes gate to avoid findings. | Dedicated-kubeconfig setup/teardown, lock/PVC restart checks, node/runtime inventory, isolation and controlled policy-CNI tests |
| SC-06 reference CouchDB | Use maintained patched reference image/source; determine whether optional Java/search components are executed. Remove unused components only through a reviewed reproducible fixture build, not hidden scanner exclusions. | Same pinned Commonlib/PouchDB differential fixture and protocol expectations; loopback/synthetic-only isolation |
| SC-07 RustFS | Obtain vendor native SBOM/source provenance and patch its runtime/vendor dependencies. A glibc variant is not automatically safer. If no supportable build exists, evaluate a maintained S3-compatible replacement without weakening the common contract. | Conditional-create races, size/hash integrity, bounded streaming, full upstream client/E2EE/reset/restart fixture and applicable provider tests |

For every rebuilt image: pin source, lockfiles, toolchain and base digests; verify supplier checksums/signatures where available; review licenses and patch notes; use controlled retrieval and offline/frozen builds where possible; emit SBOM/provenance; scan and execute the same digest on approved architectures. Building or publishing replacement images requires permission and an approved registry/ownership/patching process. Do not silently fork seven upstream products without maintainers and update SLAs.

Native runtime closure must separately inventory Rust's self-contained musl, SQLite, AWS-LC and other vendored C/assembly, including patch provenance and build flags. Runtime OS package counts and Cargo advisory results alone are insufficient. Validate supported architectures and establish a signed, reviewed binary-specific applicability/VEX process if the organization's policy permits it. The demonstrated BuildKit patch-ancestry case is an investigation input, not a blanket exception.

**Acceptance:** fresh scans and provenance/call-path evidence are tied to exactly the binaries used by CI/release. Applicable issues are fixed; other dispositions satisfy the approved closure policy. Under-investigation/unsupported/no-evidence findings stay blocking. Preserve all existing compatibility/provider/concurrency tests.

## M3 — Enforced release authorization and attestations

- Retain build-once, checksum-verified shared artifacts; do not rebuild independently between testing, scanning and release.
- Promote only reviewed protected refs after every required gate and approved finding disposition passes. A clean runtime report alone is insufficient.
- Bind source tree/revision, dependency/native materials, image/config/layer digests, platform, build identity, test/security results and policy version in signed provenance/attestations and SBOM references.
- Scope signing/OIDC/KMS authority to a protected release/attestation job, never general PR jobs. Select public/private transparency and metadata handling to match the approved policy. Avoid long-lived CI signing keys.
- Extend release verification/admission to verify trusted issuer/workflow/ref/subject, artifact digest, evidence completeness/freshness, required job outcomes and explicit deployment approval. Refuse unsigned, wrong-source/platform, stale, incomplete, substituted and unapproved artifacts.
- Treat signing as one control: independent trusted verification and builder isolation remain necessary because compromised builders can sign their own poisoned output.

**Acceptance:** negative tests reject forged reports/signatures, wrong issuer/ref/digest, missing/failed/skipped checks, stale evidence, tag substitution and unapproved deployment. No real deployment or image publication until explicitly authorized.

## M4 — Egress, devices and provider authority

### Network and TLS

Replace broad cloud egress examples in an approved production profile with default-deny and approved private endpoints or a controlled egress gateway. Restrict DNS and outbound destination/account/bucket authority, including IPv6 and shared cloud-provider ranges. An allowed provider domain/IP range alone may permit other tenants; pair network restrictions with provider endpoint policies and IAM. Preserve private HTTPS and actual Origin/auth checks; never weaken TLS verification or introduce transparent decryption of customer notes without an approved design.

Extend **only** `scripts/smoke-kubernetes.sh` with a disposable policy-enforcing CNI test profile and explicit kubeconfig on every invocation. Pin/scan any added images. Use reachable synthetic approved/denied destinations and a permissive control subject so a negative test cannot pass merely because DNS/TLS/routing was broken. Test HTTPS, DNS, unauthorized internal destinations and unintended IPv6 paths. Define an equivalent host/proxy enforcement profile for Compose; loopback port publication alone is not egress control.

### Identity, E2EE and authorized export

Preserve the upstream Basic UUID/key contract; interactive SSO/JWT challenges must not break LiveSync/PouchDB. Apply MFA/device posture and administrator approval at compatible identity/access boundaries. Keep per-device revocable vault grants, offline administration authority and separate client E2EE recovery material.

Document that authorized replication intentionally exports a granted vault. Establish managed-device/encryption configuration, compartment boundaries, device loss response and approved sharing. For stronger compartmentalization use independent installations with exclusive metadata/blob namespaces, not copied metadata over shared writable storage. Design export-volume/anomaly signals and optional capacity policies without breaking legitimate bulk replication, waiting feeds, checkpoints or retries. Do not claim content-aware server DLP over opaque client-encrypted notes.

### Provider permissions

Define and test provider-specific read/create/conditional-write/final-delete-denial policies. Separate staging cleanup authority where needed, especially Azure's current container-wide delete-capable SAS. Evaluate native workload identity/short-lived credential refresh and rotation with scoped token audiences, not broad service-account token mounting. Preserve create-only publication and exact read-back size/hash verification through credentials expiring or rotating during operations.

**Acceptance:** approved destinations and required replication work; prohibited destinations, unauthorized vault/device access, invalid TLS/Origin and final overwrite/delete attempts fail. Use authorized disposable accounts for native provider permission/rotation/interruption tests. Compilation/RustFS tests do not certify GCS/Azure/AWS/MinIO. Production enforcement is a separate authorized validation.

## M5 — Durable, privacy-safe audit and detection

Write the consistency/security guarantees **before** implementing new concurrent audit mutations:

- Approve the minimal event schema and data classification: server-generated correlation/event ID, time, operation category, approved opaque identity/scope and outcome. Never record note paths/bodies, bearer/device keys, passphrases, signed URLs or raw provider errors.
- Cover authentication/authorization decisions, read/export categories, mutations/checkpoints/reset, grant/key administration, policy decisions and recovery actions. Define how unauthenticated floods are bounded/aggregated without allowing audit storage or valid-device rate budgets to be exhausted silently.
- For required-audit operation, persist mutation audit intent atomically with the authoritative SQLite transaction before acknowledging success. Define required read-audit behavior and fail-closed startup/spool-full/sink-failure policy with the owner.
- Use a bounded durable outbox and fenced at-least-once delivery to a separately controlled immutable/auditable sink. Preserve process authority through canceled tasks, restart recovery, fairness and replay semantics. Do not replace persistent checks with a mutex or promise exactly-once delivery.
- Establish collection access control, retention, clock synchronization, redaction, alert thresholds and security-operations ownership. Detect unusual reads/volume, repeated denied access, reset/key use and audit delivery failure using metadata rather than content inspection.

**Acceptance:** authorization/race/cancellation/response-lost/restart tests show no required audit event is silently lost; spool/sink failures follow the approved fail-closed policy; delivery duplicates are identifiable; synthetic secret/path markers never enter events or reports. Alert/triage and incident exercises use synthetic data. No unbounded jobs, queues or blocking work are introduced.

## M6 — Crypto, retention and disaster recovery

- Select an approved at-rest encryption/key-custody profile for metadata, blobs and backups, including residency, separation of duties, rotation/revocation and recovery. Do not put keys or deployment specifics into source/TOML templates/images.
- If FIPS or another validated cryptographic boundary is mandatory, identify the exact module/build/platform/operating mode and validate the entire required client/server path. A library feature switch, TLS use or client E2EE label is not certification. If the selected client/platform cannot meet the mandate, block that workload rather than inventing a proprietary replacement protocol.
- Define legal retention, erasure, legal hold, backup expiry and device-replica responsibilities with the compliance owner. Preserve the current no-final-GC behavior until a protocol-aware design is approved. If mandatory erasure cannot be met, do not approve that data class. Any future deletion design must first prove revision-tree, conflict/tombstone, checkpoint, upload/replay, offline-client and recovery safety; never hand-edit internal state.
- Establish matched encrypted SQLite/blob snapshots, off-host/protected recovery copies, integrity verification and isolated restoration procedures. Restoring metadata can restore old grants: test independent revocation records and credential reissue/rotation after restore.
- Set and demonstrate RTO/RPO with supported single-writer recovery and fenced node/PVC failover. Do not add HPA, NFS, distributed writers or forced detach without fencing to satisfy availability targets.

**Acceptance:** approved crypto/retention scope is documented, authorized restore/rotation/hold/erasure scenarios meet it, restored content/auth/checkpoints are verified, and revoked access stays denied after the prescribed incident recovery. No cloud/CSI disaster-recovery claim is made from local restart tests alone.

## M7 — Final release decision and evidence

For every A/R finding publish a non-secret closure record containing owner/reviewer role, status, exact source/image/platform/policy, tests and timestamps. Keep real endpoints, identifiers, credentials, machine profiles and classified outputs outside this public repository.

Run the full correctness, feature, protocol, storage, security, SBOM and deployment gates from the repository skills against the final immutable artifacts. Add the new negative audit/identity/egress/admission/restore tests and separately authorized provider/operational checks. Recheck repository enforcement after policy changes. Make missing evidence, unsupported provider/profile, expired applicability decision and any unresolved required control fail acceptance.

An independent reviewer verifies that test data were synthetic, no secrets appear in public outputs, no findings were concealed, and the evidence matches the deployed digest. The owner then explicitly approves only the tested data classes/providers/platforms and residual-risk scope. No generic “compliant” or vulnerability-free declaration.

## Coverage and initial backlog

| Finding | Current state | Planned closure work |
|---|---|---|
| A-01 unauthenticated budget depletion | Fixed; regression retained | M1/M7 verify no regression, including audit-flood handling |
| A-02 seven upstream-image groups | Open | M2 SC-01–SC-07, M3/M7 |
| A-03 native/static inventory gap | Improved; open assurance | M2 native evidence, M6 crypto, M7 |
| A-04 content binding vs trusted release | Partial content check implemented | M0/M3/M7 |
| A-05 CI and operational acceptance | Partial; requirements unverified | M0/M1/M4–M7 |
| R-01 scanner input/output channels | Ignored-input mount fixed; output trust remains | M1, M2 tools, M7 |
| R-02 required checks/source controls | Open | M0, M3 enforcement |
| R-03 destination-bound egress | Open production profile | M4 network/IAM and M7 operational validation |
| R-04 artifact/provenance authorization | Open | M2/M3/M7 |
| R-05 build/test host compromise | Conditional exposure; unverified infrastructure | M1/M2/M3 |
| R-06 legitimate/stolen-key vault export | Product capability and policy consideration | M4 access/devices/export detection, M5, M6 |
| R-07 security audit/detection | Open | M5, M7 |
| R-08 storage authority/crypto/backups | Deployment-dependent assurance gap | M4 provider identity, M6, M7 |
| R-09 retention/erasure | Scope/policy decision pending | M0/M6/M7; block incompatible workloads |

Start with M0 decisions and M1 containment, then execute M2's findings ledger and supplier work while designing M4/M5/M6. Calendar commitments require the selected framework/provider, reviewer availability and supplier/fork ownership. Supplier fixes, validated crypto and legal retention approval can dominate the schedule; do not promise a green regulated release on a fixed date before those dependencies are known.
