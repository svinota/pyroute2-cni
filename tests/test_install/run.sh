#!/bin/bash

echo -e "\nPrepare the environment: Ubuntu $1\n"

SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"

${SCRIPT_DIR}/scripts/create-ubuntu-vm.sh $1 | tee env.sh
. env.sh

echo -e "\nRun the tests\n"

# 8<---------------------------------------------------------------------------
echo -n "Test nodes: "
NODES=`kubectl get nodes -o json | jq -r '.items[] | [ .metadata.name ] | @tsv'`
[ "${NODES}" == "cni-test" ] || { echo "Unexpected nodes: ${NODES}"; exit 1; }
echo "ok"


# 8<---------------------------------------------------------------------------
echo -n "Test CRD install: "
kubectl apply -k ./kubernetes/crds/0.1/ >/dev/null
kubectl wait --for=condition=Established crd/ipblocks.ipam.pyroute2.org --timeout=30s >/dev/null || { echo "Condition failed"; exit 1; }
kubectl apply -k ./kubernetes/releases/dev/ >/dev/null
echo "ok"


# 8<---------------------------------------------------------------------------
echo -n "Test pod start: "
for i in `seq 1 30`; do {
    kubectl -n pyroute2-cni get pods 2>/dev/null | grep pyroute2 >/dev/null && break
    sleep 1
} done
echo "ok"


# 8<---------------------------------------------------------------------------
echo -n "Test pod conditions: "
kubectl -n pyroute2-cni wait --for=condition=Ready pods --all --timeout=90s >/dev/null || { echo "Condition failed"; exit 1; }
echo "ok"


# 8<---------------------------------------------------------------------------
echo -n "Test evpn vni: "
FAILED=1
for i in `seq 1 20`; do {
    kubectl -n pyroute2-cni exec daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh -c "show evpn vni" 2>/dev/null |\
        grep l3vx-42 >/dev/null 2>&1 && { FAILED=0; break; }
    sleep 1
} done
[ "${FAILED}" -eq 0 ] || { echo "L3 VRF not found"; exit 1; }
echo "ok"


# 8<---------------------------------------------------------------------------
echo -n "Test allocations: "
KUBE_DNS=`kubectl -n kube-system get pods -l k8s-app=kube-dns -o json | jq -r '.items[] | [.status.podIP] | sort | @tsv'`
ALLOCATED=`kubectl get ipb -o json | jq -r '.items[].status.allocations | to_entries[] | select(.value != "gateway" ) | .key'`
[ "${KUBE_DNS}" == "${ALLOCATED}" ] || { echo "Unexpected allocations: ${ALLOCATED}"; exit 1; }
echo "ok"
