#!/bin/sh
# Deploys RCA to Kubernetes — see k8s/README.md for the full manual walkthrough this
# automates, including EKS-specific prerequisites (EBS CSI driver, node IAM policy, IMDS hop
# limit) a fresh cluster may be missing. No Ingress, no cert-manager: exposed via a NodePort
# Service on 30443 (see k8s/service.yaml), reachable at https://<any-node-ip>:30443 with a
# self-signed cert (SELF_SIGNED=true, see k8s/deployment.yaml) — accept the browser's "unsafe
# cert" warning. (30443, not the container's native 8443, because 8443 is outside Kubernetes'
# default NodePort range 30000-32767 and was rejected on a real cluster on actual apply, even
# though --dry-run=server didn't catch it — see k8s/README.md.)
#
# You'll also likely need a security group/firewall rule opening 30443 to wherever you're
# connecting from — node security groups typically only allow cluster-internal traffic by
# default. This script does not do that for you (scope is cluster/account-specific); see
# k8s/README.md for the exact command.
#
# The checked-in k8s/deployment.yaml keeps its REPLACE_ME image placeholder untouched; this
# script renders the real image into a temp copy at apply time instead of editing it in
# place, so nothing here ever needs a real image reference committed to the repo.
#
# Required config — set as env vars before running, or put them in a .env.k8s file next to
# this script (NOT the same file as .env, which holds FortiCNAPP credentials):
#   REGISTRY=your-registry.example.com     (required)
#   IMAGE_TAG=latest                       (optional, default: latest)
set -eu

cd "$(dirname "$0")"

if [ -f .env.k8s ]; then . ./.env.k8s; fi

: "${REGISTRY:?Set REGISTRY, e.g. REGISTRY=ghcr.io/you -- see the header comment above}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE="$REGISTRY/rca-dashboard:$IMAGE_TAG"

if [ ! -f .env ]; then
  echo "error: .env not found — copy .env.example and fill in FortiCNAPP credentials first" >&2
  exit 1
fi

echo "==> kubectl context: $(kubectl config current-context)"
echo "==> Deploying $IMAGE to namespace 'rca' (NodePort 30443, self-signed TLS)"
printf "Continue? [y/N] "
read -r CONFIRM
case "$CONFIRM" in
  y|Y|yes|YES) ;;
  *) echo "Aborted."; exit 1 ;;
esac

echo "==> Building and pushing $IMAGE (linux/amd64 — override with DOCKER_PLATFORM if your"
echo "    nodes are a different arch, e.g. arm64 Graviton)"
docker build --platform "${DOCKER_PLATFORM:-linux/amd64}" -t "$IMAGE" .
docker push "$IMAGE"

echo "==> Applying namespace"
kubectl apply -f k8s/namespace.yaml

echo "==> Syncing credentials Secret from .env"
kubectl create secret generic rca-credentials -n rca --from-env-file=.env \
  --dry-run=client -o yaml | kubectl apply -f -

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sed "s#REPLACE_ME/rca-dashboard:latest#$IMAGE#" k8s/deployment.yaml > "$TMP/deployment.yaml"
cp k8s/pvc.yaml k8s/service.yaml k8s/kustomization.yaml "$TMP/"

echo "==> Applying manifests"
kubectl apply -k "$TMP"

echo "==> Waiting for rollout"
kubectl rollout status deployment/rca -n rca --timeout=180s

echo
echo "==> Status"
kubectl get pods -n rca
echo
echo "Reachable at https://<node-ip>:30443 (self-signed cert — accept the browser warning)."
echo "You likely also need a security group/firewall rule opening 30443 to your IP — see"
echo "k8s/README.md. Find a node IP with:"
kubectl get nodes -o wide
