---
name: security-release
description: Run the repository's correctness, security, storage, feature-matrix and disposable deployment gates and prepare an evidence-based release handoff.
---

# Security and release checks

1. Read AGENTS.md and the consistency/threat model. A missing authoritative plugin is a release blocker even when storage tests pass.
2. Run scripts/check.sh and scripts/check-features.sh. Fix failures, including lints. Never ignore RustSec findings or loosen policy to get green output.
3. Run scripts/test-s3.sh. This is an actual local S3-compatible service, not a MinIO/AWS certification. Native GCS/Azure contract tests require separately authorized disposable credentials; do not use a real account or vault by default.
4. Build `docker build -t obsidian-sync:local .`; verify the final stage remains Distroless static/nonroot with only the binary added. Run scripts/scan-security.sh AFTER the final source rebuild. Record image ID, scanner/advisory versions/timestamps, scope and unresolved findings. No scanner proves vulnerability freedom.
5. Run scripts/validate-deployments.sh, scripts/smoke-compose.sh and scripts/smoke-kubernetes.sh. The latter creates its own kind cluster/kubeconfig. Never invoke kubectl against the current context or publish an image. Readiness must stay 503 until real plugin fixtures pass. NetworkPolicy needs separate enforcement testing with a policy-aware CNI.
6. Run scripts/benchmark.sh on an otherwise idle machine. Record CPU, RAM, OS, workload, samples, throughput, p50/p95/p99, and peak RSS. Distinguish core measurements from network/plugin performance; three attachment samples are not robust tail statistics.
7. Check backup restoration tests; do not claim a cloud/PVC disaster-recovery drill unless actually performed. Follow maintain-docs to update docs/results.md and acknowledge reviewed source drift.
8. Handoff implemented functionality, executed test results, scan evidence, compatibility status, benchmarks and blocked checks. Do not release production acceptance while protocol/provider/isolation gates remain unmet.
