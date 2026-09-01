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

# This script lives in k8s/, but Dockerfile/.env/.env.k8s live one level up in rca_ui/ — cd
# there so relative paths below (Dockerfile via `docker build .`, .env, .env.k8s) resolve
# correctly regardless of where this script is invoked from. k8s/-relative paths further down
# (namespace.yaml, deployment.yaml, etc.) are then written as `k8s/...` from that root.
cd "$(dirname "$0")/.."

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
cp k8s/namespace.yaml k8s/pvc.yaml k8s/service.yaml k8s/kustomization.yaml "$TMP/"

echo "==> Applying manifests"
kubectl apply -k "$TMP"

echo "==> Waiting for rollout"
kubectl rollout status deployment/rca -n rca --timeout=180s

echo
echo "==> Status"
kubectl get pods -n rca

# Prefer the node's AWS public DNS FQDN (ExternalDNS, e.g. ec2-x-x-x-x.<region>.compute.
# amazonaws.com) over a bare IP — works the same for the self-signed cert either way, but a
# FQDN is stable across an EC2 instance's public IP changing on stop/start, and is what
# EKS/AWS itself calls the address. Falls back to ExternalIP (works on non-AWS clusters, or
# if ExternalDNS isn't populated), and finally to a private-IP note if neither is present.
# Retries a few times as defense-in-depth against genuine transient API-server hiccups. (The
# CD workflow's version of this same lookup once failed hard here too, but for a different,
# non-transient reason specific to *that* context — its dedicated IAM user lacked cluster-
# scoped permission to read nodes at all; see rca-deploy.yml's header comment. This script
# runs with your own broader kubectl credentials, so that particular failure mode doesn't
# apply here.)
NODE_ADDR=""
for _ in 1 2 3 4 5; do
  NODE_ADDR="$(kubectl get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="ExternalDNS")]}{.address}{"\n"}{end}{end}' 2>/dev/null | head -1)"
  [ -n "$NODE_ADDR" ] && break
  NODE_ADDR="$(kubectl get nodes -o jsonpath='{range .items[*]}{range .status.addresses[?(@.type=="ExternalIP")]}{.address}{"\n"}{end}{end}' 2>/dev/null | head -1)"
  [ -n "$NODE_ADDR" ] && break
  sleep 3
done

echo
if [ -n "$NODE_ADDR" ]; then
  echo "Reachable at https://$NODE_ADDR:30443 (self-signed cert — accept the browser warning)."
else
  echo "No external node address found after 5 attempts — node IPs may be private-only on"
  echo "this cluster, or kubectl is having trouble reaching the API server. Node IPs:"
  kubectl get nodes -o wide
fi
echo "You likely also need a security group/firewall rule opening 30443 to your IP — see"
echo "k8s/README.md."
