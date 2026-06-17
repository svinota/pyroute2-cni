#!/bin/bash

./examples/scripts/create-ubuntu-vm.sh | tee env.sh
. env.sh

NODES=`kubectl get nodes -o json | jq -r '.items[] | [ .metadata.name ] | @tsv'`

echo -n "Test nodes: "
[ "${NODES}" == "cni-test" ] || { echo "Unexpected nodes: ${NODES}"; exit 1; }
echo "ok"


kubectl apply -k ./kubernetes/crds/0.1/ >/dev/null
kubectl wait --for=condition=Established crd/ipblocks.ipam.pyroute2.org >/dev/null
kubectl apply -k ./kubernetes/releases/0.1.0/ >/dev/null


echo -n "Test evpn vni: "
FAILED=1
for i in `seq 1 60`; do {
    kubectl -n pyroute2-cni exec daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh -c "show evpn vni" 2>/dev/null |\
        grep l3vx-42 >/dev/null 2>&1 && { FAILED=0; break; }
    sleep 1
} done
[ "${FAILED}" -eq 0 ] || { echo "L3 VRF not found"; exit 1; }
echo "ok"


echo -n "Test allocations: "
KUBE_DNS=`kubectl -n kube-system get pods -l k8s-app=kube-dns -o json | jq -r '.items[] | [.status.podIP] | sort | @tsv'`
ALLOCATED=`kubectl get ipb -o json | jq -r '.items[].status.allocations | to_entries[] | select(.value != "gateway" ) | .key'`
[ "${KUBE_DNS}" == "${ALLOCATED}" ] || { echo "Unexpected allocations: ${ALLOCATED}"; exit 1; }
echo "ok"
