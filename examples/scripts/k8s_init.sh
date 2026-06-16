#!/bin/bash

IP_ADDRESS="`ip -j ro get 1.1.1.1 | jq -r '.[0].prefsrc'`"

sudo kubeadm init \
    --pod-network-cidr=10.244.0.0/16 \
    --apiserver-cert-extra-sans=localhost \
    --control-plane-endpoint="$IP_ADDRESS:6443"

kubectl \
    --kubeconfig /etc/kubernetes/admin.conf \
    taint node --all \
    node-role.kubernetes.io/control-plane:NoSchedule-
