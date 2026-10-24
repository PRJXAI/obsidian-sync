# Regulated-environment security and exfiltration assessment

## Decision

**Do not approve this configuration for highly regulated production data yet.** The repository has meaningful isolation/integrity controls, but the currently verified controls do not establish regulated-environment readiness. Blocking scanner findings, unenforced repository checks, broad sample egress, incomplete audit/cryptographic assurance and unsigned release evidence need resolution or a formally reviewed, evidence-backed applicability decision.

This assessment does **not** establish that any image is malicious, that exfiltration has occurred, or that every scanner match is exploitable. It assesses first-party code/configuration, current CI reports, selected vendor advisories and repository settings. No production vaults, hosts, provider accounts, ACLs or real credentials were inspected. No exfiltration feature or offensive payload was added; validation used synthetic local fixtures only.

No jurisdiction, data classification or mandated control framework was specified. The findings below are control gaps and risk decisions, not a legal opinion, certification or a claim that every regulated workload has identical requirements.

## Scanner retirement follow-up

The current Rust pipeline uses [Syft → native SBOM → offline Grype](scanner-pipeline.md) exclusively; the seven-image table below records the prior Trivy baseline/exposure, not active scanner selection. The owner explicitly retired Trivy, its image pin/comparison commands and transition gate. The earlier same-config amd64 comparison's 27 baseline-only pairs remain historical investigation evidence, not reviewed advisory closure. Current Grype builder/tool matches and scan errors still fail security and Required CI. Raw match counts and the retirement decision do not establish exploitability or regulatory readiness.

## What the seven baseline image findings mean

These images are build, test or security-tool dependencies, **not ancestors of the final Distroless runtime**, which adds only the Rust executable. Their vulnerabilities can still matter through CI compromise, artifact poisoning, scanner input/output handling or future reuse outside disposable tests. Runtime/Cargo scans also do not reconstruct every statically linked native component.

| Component | Current use and exposure | Assessment |
|---|---|---|
| Syft | Offline container, networking disabled, read-only image/curated-manifest inputs, writable SBOM output, no Docker socket | Go TLS/X.509 findings such as CVE-2026-111943 do not demonstrate an active TLS attack path in this offline invocation. A parser compromise could still tamper with or copy input into output. Supplier patching and output trust remain relevant. |
| Trivy | Reads exported runtime/builder archives or public registry images; network is enabled for advisory/registry retrieval; writable cache/reports; no Docker socket | Network-dependent paths deserve review. CVE-2026-111497 is reported against an installed Brotli OS library; the report alone does not prove the Go scanner loads or invokes that library. UNKNOWN musl/OpenPGP entries are unresolved, not evidence of malware. |
| Gitleaks | Offline source/history scanning; receives potentially secret-bearing Git data and writes reports | Archive-related findings include denial-of-service conditions; they do not, by themselves, prove code execution or exfiltration. The former full-working-tree history mount unnecessarily exposed ignored files. This assessment removes that mount and adds isolation regressions. |
| Dockerfile frontend / BuildKit | A pinned frontend participates in privileged build infrastructure and processes repository-controlled build instructions | High CI integrity concern, but package attribution needs correction before treating every hit as an exploitable daemon flaw. The frontend and host BuildKit daemon are different components. See the source-version example below. |
| kind node | Disposable nested Kubernetes/container-runtime test node, not a production cluster | containerd privilege/file-access and gRPC authorization matches require attention. Several targets are bundled helpers, not proof that the vulnerable path is enabled. The stronger node privileges make ephemeral runner isolation essential even when the workload is synthetic. |
| Reference CouchDB | Loopback-published disposable fixture with generated credentials and data | No production vault is mounted. Optional bundled Java/search libraries are not shown to be active by the version report. A fixture compromise could nevertheless attack its network/CI environment; loopback publication is an ingress restriction, not outbound containment. |
| RustFS | Non-root/read-only disposable S3-compatible fixture with generated keys, tmpfs data and no real bucket | The OS Brotli/musl matches do not prove the Rust binary reaches those vulnerable functions. Its native dependency graph needs vendor SBOM/source evidence; the first-party Cargo audit does not cover another vendor's compiled binary. |

Additional applicability cautions:

- Gitleaks' two Critical OpenSSL package associations include CVE-2026-31789, whose stated condition is 32-bit certificate processing. The inspected pipeline images are 64-bit. Do not equate those two package matches with two demonstrated remote-code-execution paths.
- The frontend report identifies `github.com/moby/buildkit` using the pseudo-version `v0.0.0-20261007191819-f5b59a1f2fb2`. Simple version comparison can misattribute old advisories. GitHub ancestry shows upstream fix commit `64bbec89ca43dd95b2853edeca240c33c6729910` for CVE-2026-61711 is an ancestor of that reported source revision. This is evidence for a source-level applicability review, not permission to ignore all BuildKit findings or proof of the installed daemon's state.
- The description of CVE-2026-33747 distinguishes an untrusted custom frontend from the documented well-known `docker/dockerfile` frontend case. An untrusted pull request can still change build inputs; the workflow must not rely on package version labels alone as a security boundary.
- Go CVEs against a module included in a CLI/helper do not establish that it exposes the affected HTTP/gRPC server API. Conversely, missing symbols or an apparently unused helper is not a blanket assurance against all paths.

Keep findings **under investigation** unless the exact binary, platform, configuration and vendor fix/reachability evidence support a reviewed applicability decision. No advisory ignore, severity filter or automatic VEX exception was introduced. The expanded gate remains failing.

## Data-exfiltration paths and control gaps

### R-01 — Scanner input and output channels — HIGH, excessive history mount fixed; residual trust remains

Before this change, the history scan mounted the whole checkout read-only. That included ignored operator `.env`, data, secret and working directories whenever they existed locally. The scanner intentionally ran as the caller, so filesystem ownership did not conceal those inputs. No exploit was needed to identify the excessive exposure; no actual private files were opened for this assessment.

The history scan now receives a fresh, independent **bare Git mirror only**, with the origin configuration removed and no local hardlinks/alternates. It scans all reachable refs, including detached CI HEAD history, while ignored working-tree files are absent. The normal source scan continues to stage only Git-eligible candidates and reject symlinks. Synthetic `.env` and data canaries verify the minimized mounts; no real credential or network sink is used.

`--network none` prevents ordinary outbound network connectivity in the scanner namespace, but it is **not full data-loss prevention**. A compromised tool can copy inputs into stdout, a writable report or a poisoned SBOM; an uploader or operator can subsequently disclose that output. Public-repository artifacts/logs must therefore contain only public source and synthetic data, never regulated customer inputs. Scanners legitimately inspecting Git secrets still require trusted tooling and controlled report handling; mount minimization does not make arbitrary scanner code trustworthy.

### R-02 — Required checks are not enforced — HIGH, open

Read-only repository API inspection found `main` unprotected and zero repository rulesets. Workflow token defaults are read-only and cannot approve pull requests, which is positive, but a failed workflow does not by itself prevent a permitted writer from pushing code or an operator from deploying an artifact.

Before regulated use, require protected main/release refs, reviewed changes to workflows/build inputs, independent approval or a documented equivalent, required security checks and restricted bypass privileges. Keep untrusted PR execution on isolated ephemeral runners with no production credentials, tailnet, cluster context or privileged organizational network access. No repository protection settings were changed by this assessment.

### R-03 — Outbound traffic is not destination-bound — HIGH, egress sandbox deferred; production enforcement unverified

The base Kubernetes policy declares no egress, but all cloud overlays permit TCP/443 to `0.0.0.0/0` except loopback/link-local ranges and allow DNS to kube-system. These are explicitly samples requiring narrowing, not provider-specific production allowlists. The Compose service has loopback-only inbound publication but no application-destination outbound firewall.

If code execution, credentials or trusted configuration are compromised, these configurations permit a plausible HTTPS/DNS exfiltration path. This is not evidence of a client-controlled SSRF bypass: the current S3 endpoint is operator-configured, HTTPS-validated, redirect-disabled and proxy-disabled.

Require approved provider endpoints/private endpoints or a controlled egress gateway, constrained DNS resolution, destination/identity enforcement and denied-path tests under a policy-enforcing CNI. Monitor connection/volume metadata without logging content or signed URLs. No real egress policy was tested or modified.

### R-04 — CI artifact integrity is not release authorization — HIGH, open

Checksummed shared image archives, immutable identifiers and `cargo xtask verify-release` reduce tag/config/layer substitution. They do not prove that the builder or scanner is uncompromised. The helper checks a trusted clean **runtime** report; it does not independently require the whole supply-chain job to pass or enforce an approved release identity/authorization policy. A poisoned builder can produce poisoned code and internally consistent hashes.

Require a protected release process with successful applicable security gates, approved provenance/attestations bound to source and artifact digest, controlled builders, independently verified supplier inputs, and deployment admission/approval. SBOMs are inventory, not a malware verdict or a signature. Signing a compromised builder's output alone does not solve this problem. No production release is authorized while the current gate is unresolved.

### R-05 — Build/test host compromise — HIGH conditional CI integrity impact, not demonstrated production compromise

A genuinely reachable BuildKit/container-runtime issue could cross a build/test isolation boundary or poison artifacts that are deployed later. kind needs stronger nested-runtime privileges than the non-root server; a nested runtime's “host” is not automatically the production host, and this repository uses disposable hosted CI rather than production cluster credentials. Those facts reduce current production confidentiality exposure but do not justify running the same tests on a shared regulated host.

Use ephemeral runner isolation, reviewed/patched build and test infrastructure, controlled dependency retrieval and restricted egress. Do not mount real data, Docker credentials or customer secrets into test services. Public PRs execute arbitrary code by design; do not introduce production secrets into their jobs.

### R-06 — Authorized replication can export a vault — HIGH policy consideration, not an authorization bypass

Current credentials are independently revocable, high-entropy and vault-scoped; negative tests cover wrong-vault, read-only, revoked and malformed identities. An authorized read device can legitimately replicate its granted vault. A stolen device key plus network access can exercise that capability; if the endpoint is also compromised, client encryption material may be exposed separately.

Client E2EE is supported but **not mandatory or server-enforced**. The server can accept plaintext JSON, and metadata/access patterns remain observable. A runtime compromise can read its mounted data/provider credentials; one process has installation-wide authority. For sensitive compartments require managed devices, posture/MFA at the appropriate access/admin boundaries, tailnet ACL review, validated client encryption/key custody and a defined least-privilege sharing model. Rate/transfer bounds are not content-aware DLP or a lifetime export quota.

### R-07 — Security auditability and detection — HIGH, open

First-party tracing currently records startup, shutdown and classified operation failure, not a complete durable security audit trail of authentication/authorization decisions, reads, mutations, reset capability use, key administration or bulk-export activity. Avoiding content/credential logging is correct, but it does not establish auditability or detection of authorized data theft.

Define approved security-event metadata, immutable/isolated collection, access control, retention, time synchronization, alerting and incident procedures. Events should contain only the approved principal/vault/request category, outcome and correlation/time fields, not note paths/bodies, keys or provider error sources. Do not “fix” auditability by indiscriminately logging requests. Persisted integrity jobs are not a security audit log.

### R-08 — Storage credentials, backups and cryptographic assurance — HIGH assurance gap, deployment-dependent

Filesystem publication and SQLite integrity checks do not enforce provider IAM. In particular the supported Azure container SAS includes read/create/write/delete for staging cleanup across its container; a stolen credential can attempt operations outside the application's no-final-delete trait. Provider immutability policies may independently deny such operations, but none was verified here. S3/GCS also need independently reviewed prefix/conditional-write/cleanup permissions.

Use least-privilege provider policies, separate staging authority where necessary, protected recovery copies, tested restoration, encrypted persistent volumes/backups and governed key rotation/residency. The repository does not implement SQLite transparent encryption, mandatory KMS-backed at-rest encryption, automatic workload-identity rotation, or a FIPS-validated operational profile. Rustls/AWS-LC or client E2EE alone is not evidence of FIPS validation; that requirement must be established for the specific regulatory scope and build.

### R-09 — Retention and erasure requirements — Policy-dependent blocker

Indefinite revision/blob/replay retention supports integrity and recovery but is not a complete legal retention, erasure or legal-hold policy. Requirements differ across sectors, purposes and jurisdictions; no automatic GDPR/HIPAA/financial compliance claim is justified. Determine the applicable retention, archive, recovery and deletion rules before production acceptance. Do not add manual deletion or garbage collection that breaks the protocol's revision/checkpoint guarantees.

The actionable [security remediation plan](security-remediation-plan.md) maps every A/R finding to prioritized milestones, accountable roles, dependencies and closure tests. Repository-side implementation has started in Rust; the plan is not evidence that the gaps have already been closed. A fail-closed CI aggregate, read-only approval-policy preflight, bounded scanner roots, local findings ledger and public count/status summaries are foundations only. Required repository protections/reviewer identities, signed release authorization, private durable raw-evidence archival, audit/crypto/retention and operational validation remain open. The owner explicitly deferred general egress-sandbox support; broad cloud samples are unchanged and no destination-bound production control is claimed.

## Acceptance plan

Before any regulated/customer data:

1. Define data classification, jurisdictions, applicable framework and approval owner; keep real data/credentials out of this public repository, CI and tool reports.
2. Enforce protected-source/release checks and approved runner boundaries; resolve supplier vulnerabilities or complete vendor-supported binary/platform applicability reviews. Preserve the failing gate until that process is approved.
3. Establish signed, independently verified artifact/provenance policy and deployment authorization. Do not equate a runtime-only clean report with an accepted complete supply chain.
4. Validate destination-bound egress/private TLS, provider IAM/immutability, encryption/key custody and residency under approved disposable tests, then separately authorized operational validation.
5. Implement and verify an approved security audit/detection pipeline and incident response, plus matched encrypted backup/restoration and a protocol-aware retention policy.

Typical evidence areas include NIST SP 800-53 AC/IA, AU, SC, SI-2/RA-5, SR/SA and CP controls; ISO 27001 access, logging, vulnerability, supplier, DLP and cryptographic controls; SOC 2 access/monitoring criteria; and privacy-law security/retention requirements where applicable. This mapping is an assessment aid, not a certification or assertion that those frameworks require the same implementation.

## Evidence and limits

- First-party source/configuration review: CI workflow, scanner/SBOM scripts, auth/transport/storage, sample Compose/NetworkPolicy and release-content verification. Existing authorization/race/restart tests remain relevant but do not prove DLP or regulatory compliance.
- Current CI artifacts: complete ten-image amd64 scan reports from [run 40079991599](https://github.com/PRJXAI/obsidian-sync/actions/runs/40079991599), with seven image pins reporting findings. Alternative-image checks also remained non-clean; package presence is not execution evidence.
- Vendor source evidence: [CVE-2026-61711 advisory](https://github.com/moby/buildkit/security/advisories/GHSA-7236-3392-c5c6), [upstream fix](https://github.com/moby/buildkit/commit/64bbec89ca43dd95b2853edeca240c33c6729910), and [reported frontend revision](https://github.com/moby/buildkit/commit/f5b59a1f2fb2). This does not identify or certify the CI/production daemon version.
- Tests: synthetic ignored-file/detached-history regression, retained scanner UID/capability guards, and actual source/history/runtime/builder scan execution with the bare mirror. The secret scans found no credentials in their tested inputs. No real sensitive-data transmission, production traffic capture, exploit execution or forensic investigation was performed.
- Raw local evidence stays ignored under `.work/regulated-assessment/`. It contains no production vault data or operational credentials; no private host/machine profile is included in this document.

See [threat model](threat-model.md), [original audit](security-audit.md), [results](results.md), [storage](storage.md) and [operations](operations.md) for authoritative constraints and remaining acceptance gates.
