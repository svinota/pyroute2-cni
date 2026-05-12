#!/usr/bin/env bash
set -euo pipefail

BASE_URL="https://raw.githubusercontent.com/svinota/pyroute2-cni/refs/heads/main/kubernetes"

kubectl apply -f "${BASE_URL}/crd.yaml"
kubectl wait --for=condition=Established crd/ipblocks.ipam.pyroute2.org --timeout=120s

kubectl apply -f "${BASE_URL}/namespace.yaml"
kubectl apply -f "${BASE_URL}/rbac.yaml"
kubectl apply -f "${BASE_URL}/config.yaml"
kubectl apply -f "${BASE_URL}/daemonset.yaml"
