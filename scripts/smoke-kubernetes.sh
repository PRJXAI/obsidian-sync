#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Never read/use the operator's current kubeconfig. kind is the only cluster creator.
work=$(mktemp -d)
cluster="obsidian-sync-smoke-$$"
cleanup() { kind delete cluster --name "$cluster" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT
kind create cluster --name "$cluster" --kubeconfig "$work/kubeconfig" --wait 120s \
  --image kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5
k() { kubectl --kubeconfig "$work/kubeconfig" "$@"; }
kind load docker-image obsidian-sync:local --name "$cluster"
k apply -k deploy/kustomize/overlays/filesystem
for overlay in filesystem s3 gcs azure; do
  k apply --dry-run=server -k "deploy/kustomize/overlays/$overlay" > /dev/null
done
wait_running() {
  for _ in $(seq 1 90); do
    if k -n obsidian-sync wait --for=jsonpath='{.status.phase}'=Running pod -l app=obsidian-sync --timeout=2s; then return; fi
    sleep 1
  done
  return 1
}
wait_running
k -n obsidian-sync port-forward deployment/obsidian-sync 18090:8080 > "$work/port-forward.log" 2>&1 &
forward=$!
for _ in $(seq 1 60); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18090/health/live || true)" = 204 ]; then break; fi
  sleep 1
done
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18090/health/live)" = 204 ]
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18090/health/ready)" = 204 ]
if k -n obsidian-sync exec deployment/obsidian-sync -- /server create-vault > "$work/lock.log" 2>&1; then
  printf 'ERROR: runtime writer fencing failed\n' >&2; exit 1
fi
grep -q 'another writer owns' "$work/lock.log"
k -n obsidian-sync delete pod -l app=obsidian-sync --wait=true
wait_running
k -n obsidian-sync exec deployment/obsidian-sync -- /server --version
kill "$forward" 2>/dev/null || true
wait "$forward" 2>/dev/null || true
printf 'Disposable Kubernetes smoke passed; LiveSync adapter readiness is 204. Default kind CNI does not verify NetworkPolicy enforcement.\n'
