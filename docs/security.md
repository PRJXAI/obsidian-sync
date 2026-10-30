# Security and accepted risks

## Current-stack decision

On **2026-10-30**, after reviewing advisory prerequisites, actual invocation patterns and partial binary evidence, the repository owner accepted the investigated current-stack risks and requested image delivery. This includes known findings with published fixes. It is a deployment/tooling trade-off—not a claim that all matches are false positives, every exploit path is excluded or these versions are universally optimal.

The machine-readable snapshot is `xtask/src/accepted-risks.json`; `xtask/src/risk.rs` enforces it **after** ordinary report validation. Registry entries bind exact platform/configuration identities. The populated builder binds its Dockerfile and exact package/advisory identities; its reference measurement is arm64, and the policy explicitly covers the same named matches on both Linux 64-bit targets without claiming native amd64 measurement.

Rules include package/version/type/location, advisory/namespace/severity/fix/related identities and maximum occurrences. All effective/suppressed matches remain in the raw report and counts. Reports classify **accepted-risk**, never fixed or vulnerability-free. New or changed findings, extra duplicates and changed subject scope do not inherit acceptance. Source/runtime findings have no acceptance profile. Neither inventory gaps nor scanner errors are accepted by this policy.

Changing the snapshot requires a new reviewed owner decision. Do not generate acceptance automatically from a future scan, add broad severity rules, enable `--only-fixed`, suppress warnings or rewrite raw reports.

## Exposure assessment

- Windows-only `os.Root` behavior does not match Linux subjects. The cited 32-bit OpenSSL/Perl triggers differ from reviewed 64-bit conditions; native builder Perl reports 8-byte pointers/integers. These observations do not dismiss other advisories.
- Historical K3s testing ran a private API service with conditional HTTP/2/gRPC availability risks. The owner retired live Kubernetes testing and its three image dependencies; those findings are not fixed, but those services are no longer active release/test assets.
- The active host builder was observed at BuildKit **0.27.1**, below the **0.31.1** custom-frontend Seccomp/AppArmor fix. A pinned frontend limits substitution; it does not authenticate benign behavior or patch the host daemon. No bypass, privileged tracing or host upgrade was performed.
- Docker compressed-upload execution requires an explicitly compressed archive sent through the archive API; ordinary `docker cp` is excluded by upstream. Destination-escaping extraction is a different vulnerability and requires review of actual extractors.
- Gitleaks defaults to archive traversal disabled; the repository enables neither it nor HTTP diagnostics and selects JSON output. Other parser/decoder/native paths remain relevant. Offline scanners can still consume malicious files or poison reports.
- Symbol inspection of nine Linux arm64 Go binaries found usable metadata for only the frontend/Gitleaks. Seven missing inventories of symbols are **not absence of vulnerable code**. Binary mode computes no call graph; no automated VEX follows.

No end-to-end exploit was attempted or demonstrated. Retained source/runtime scans have zero matches; this is not proof that all static native code is inventoried or safe. Historical investigations and failures remain in Git/private evidence, not a parallel set of current policy pages.

## Controls that remain mandatory

- **Authorization:** random 256-bit per-device keys; Basic username must match the principal UUID. Reauthorize current vault grants for every data/checkpoint/reset operation. Negative wrong-vault/read-only/revoked/credential tests remain required.
- **Integrity:** persistent SQLite transactions and process lock; immutable hash/size-verified create-only blobs; revision conflicts/tombstones/checkpoints and first-body-wins replay. No mutex substitute, final-data GC or manual backend edits.
- **Resource control:** bounded sockets/admission/body/response/JSON complexity/CPU/blocking/storage/job queues and finite operation/drain deadlines. Authenticate before spending authenticated rate budgets. Limits are capacity policies, not DoS immunity.
- **Private access:** exact CORS, no public ingress/Funnel, remote Basic/Bearer only through private HTTPS. Tailscale is not authorization.
- **CI inputs/outputs:** public/synthetic data only; minimized read-only source inputs and independent bare history. No scanner socket, operator HOME/kubeconfig or writable input/output alias. Fresh separately retrieved advisory data, bounded captures and cancellation-safe cleanup.
- **Evidence:** immutable archive/config/layer/source bindings, complete inventories, all severities/suppressions, explicit accepted/blocking counts and failure on malformed/stale/substituted/missing evidence. An empty active catalog remains an error, not zero findings. The former pause inventory gap is preserved historically; its entire test dependency was retired, not waived.

DevSecOps source and released packages must be public. A private token, authenticated host cache or public source repository alone is not anonymous package availability; no consumer reader-token/private-export workaround remains. The producer gates delivery artifacts on anonymous index/native/config access after provenance. Existing package visibility requires owner UI action with appropriate package authority.

The producer's accepted risks do not automatically authorize consumer matches; the consumer applies its own explicit snapshot. A tool container does not replace a compiler, daemon, privileged node or S3 service. Keep the full host cargo-deny gate until its container replacement proves equivalent coverage.

## Operational and regulated-data limits

| Boundary | Required operator control / remaining limitation |
|---|---|
| Source and release authority | Protected reviewed refs, required checks, restricted bypass and independently trusted provenance/admission. Repository code does not configure organization protections or certify reviewer independence. |
| Runner compromise | Isolated ephemeral workers without production credentials/tailnet/real contexts. OS/root, same-UID processes and local Docker are trusted; no race-free protection against those actors is claimed. |
| Egress and output | Cloud samples allow broad HTTPS/DNS and Compose loopback limits ingress only. Destination/identity-bound egress and policy-CNI negative tests remain operator work. Networking disabled is not DLP: reports can encode input. |
| Authorized export | A granted read device can replicate its vault by design. Manage devices, key custody/revocation, compartments and client E2EE. E2EE is client-controlled, not mandatory server enforcement. |
| Security audit | Startup/classified operational tracing is not a complete durable security audit/detection trail. An approved privacy-safe schema/sink/retention/failure policy is not implemented. Never fix that by logging note paths/bodies, tokens or provider errors. |
| Storage authority | Provider IAM/conditional writes/staging lifecycle need native tests. Azure's supported SAS includes delete authority for staging; application no-final-delete behavior is not provider immutability enforcement. Credentials currently rotate through restart. |
| Crypto and recovery | No SQLite transparent encryption, mandatory KMS profile, automatic workload identity refresh or validated FIPS operational profile is established. Require protected matched encrypted backups and authorized restore/revocation drills. |
| Retention/erasure | Indefinite revision/blob/replay retention is intentional. Approve a protocol-aware erasure/retention design before deletion; do not approve incompatible data classes by pretending GC exists. |
| Evidence/storage | Raw findings/logs remain private pending an owner-approved durable archive. Archive/report caps do not impose hard quotas on caches, provider staging or Docker/host storage. |

The read-only `cargo xtask check-release-policy --source-revision SHA` remains fail-closed for unconfigured deployment scope, reviewer/source protections and closure evidence. Current-stack acceptance does not mark those controls verified. Generic image publication is not that deployment approval.

Risk acceptance for the current stack is **not regulated-production certification**, approval of real-provider/GUI/CNI/DR checks, a change to data retention or permission to access a real vault/cluster/account. See [operations](operations.md), [trust model](threat-model.md), [scanner contract](scanner-pipeline.md) and [release engineering](releases.md).
