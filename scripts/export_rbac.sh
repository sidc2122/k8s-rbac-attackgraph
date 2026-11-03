#!/usr/bin/env bash
#
# export_rbac.sh - photocopy a live cluster's RBAC into a single YAML file
# so the analyzer can read it.
#
# Usage:
#   ./scripts/export_rbac.sh                 # writes cluster-rbac.yaml
#   ./scripts/export_rbac.sh my-dump.yaml    # writes my-dump.yaml
#
# Requires: kubectl configured to talk to the target cluster
#           (read-only permissions are enough; this only reads).

set -euo pipefail

OUTPUT="${1:-cluster-rbac.yaml}"

RESOURCES="roles,clusterroles,rolebindings,clusterrolebindings,serviceaccounts,pods"

echo "Exporting RBAC from the current kubectl context..."
kubectl config current-context

kubectl get ${RESOURCES} --all-namespaces -o yaml > "${OUTPUT}"

echo "Done. Wrote ${OUTPUT}"
echo "Now run:  python -m rbacgraph.cli analyze ${OUTPUT}"
