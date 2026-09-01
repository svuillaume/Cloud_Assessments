#!/bin/sh
# Tears down RCA from Kubernetes — see k8s/README.md's "Tear down" section for the manual
# walkthrough this automates. Three modes, picked by flag:
#
#   ./rca_tear_down.sh              full teardown (default) — deletes the whole `rca`
#                                    namespace, cascading to the Deployment, Service, PVC
#                                    (+ underlying EBS volume, gp2's reclaim policy is
#                                    Delete), and Secret. Cached data (cache.json) is lost.
#   ./rca_tear_down.sh --keep-pvc   deletes the Deployment/Service/Secret but leaves the
#                                    namespace and PVC in place, so a future deploy_k8s.sh
#                                    run picks the persisted cache.json back up.
#   ./rca_tear_down.sh --restart    deletes just the running pod(s) — the Deployment
#                                    immediately recreates a fresh one. Not really a
#                                    "teardown"; included here since it's the same
#                                    kubectl-delete-by-label pattern.
#
# None of this touches cluster-level resources (the EKS cluster itself, the
# aws-ebs-csi-driver add-on, the AmazonEBSCSIDriverPolicy IAM attachment, or any security
# group rule opened for external access) — those are left in place on purpose so a later
# deploy_k8s.sh run doesn't need to repeat the fresh-cluster prerequisites. See
# k8s/README.md's "Tear down" section for the (manual, account-specific) commands to reverse
# those too.
set -eu

MODE="full"
case "${1:-}" in
  ""|--full) MODE="full" ;;
  --keep-pvc) MODE="keep-pvc" ;;
  --restart) MODE="restart" ;;
  *)
    echo "usage: $0 [--full|--keep-pvc|--restart]" >&2
    exit 1
    ;;
esac

if ! kubectl get namespace rca >/dev/null 2>&1; then
  echo "Namespace 'rca' not found — nothing to tear down."
  exit 0
fi

echo "==> kubectl context: $(kubectl config current-context)"
case "$MODE" in
  full)
    echo "==> Mode: full — deletes namespace 'rca' (Deployment, Service, PVC + data, Secret)"
    ;;
  keep-pvc)
    echo "==> Mode: keep-pvc — deletes Deployment/Service/Secret, leaves namespace + PVC (cache.json preserved)"
    ;;
  restart)
    echo "==> Mode: restart — deletes running pod(s) only; the Deployment recreates them"
    ;;
esac
printf "Continue? [y/N] "
read -r CONFIRM
case "$CONFIRM" in
  y|Y|yes|YES) ;;
  *) echo "Aborted."; exit 1 ;;
esac

case "$MODE" in
  full)
    kubectl delete namespace rca
    ;;
  keep-pvc)
    kubectl delete deployment,service,secret -n rca -l app=rca --ignore-not-found
    echo
    echo "PVC left in place:"
    kubectl get pvc -n rca
    ;;
  restart)
    kubectl delete pod -n rca -l app=rca --ignore-not-found
    echo
    echo "Deployment will recreate the pod shortly:"
    kubectl get pods -n rca
    ;;
esac
