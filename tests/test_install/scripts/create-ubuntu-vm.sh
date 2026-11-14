#!/bin/bash

export LIBVIRT_DEFAULT_URI=qemu:///system

[ "$1" = "ubuntu24" ] && {
    export IMAGE_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
    export IMAGE_BASE="https://cloud-images.ubuntu.com/releases/noble/release/"
} ||:

[ "$1" = "ubuntu25" ] && {
    export IMAGE_NAME="ubuntu-25.10-server-cloudimg-amd64.img"
    export IMAGE_BASE="https://cloud-images.ubuntu.com/releases/questing/release/"
} ||:

[ "$1" = "ubuntu26" ] && {
    export IMAGE_NAME="ubuntu-26.04-server-cloudimg-amd64.img"
    export IMAGE_BASE="https://cloud-images.ubuntu.com/releases/resolute/release/"
} ||:

[ -z "${IMAGE_NAME}" -o -z "${IMAGE_BASE}" ] && { echo -e "# Image not defined\nexit 100"; exit 100; }

VM_BASE="cni-test"
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
WORK_DIR="vm-test"
TMP_DIR="tmp"

mkdir -p ${WORK_DIR}
mkdir -p ${TMP_DIR}
pushd ${WORK_DIR} >/dev/null


# sanity check
ls -1 |\
    grep -v ${IMAGE_NAME} |\
    wc -l |\
    grep ^0 >/dev/null || { echo "# Start in an empty directory"; exit 1; }

for i in ssh-keygen jq curl tofu ansible-playbook; do {
    echo -n "# Check $i ... "
    which $i >/dev/null 2>&1 || { echo "# required $i missing"; exit 2; }
    echo "ok"
} done

[ -f "../${TMP_DIR}/${IMAGE_NAME}" ] || {
    echo -n "# Download Ubuntu cloud image ... "
    curl -SsLo ../${TMP_DIR}/${IMAGE_NAME} ${IMAGE_BASE}/${IMAGE_NAME} >/dev/null && echo "ok"
}

[ -f "${IMAGE_NAME}" ] || {
    cp ../${TMP_DIR}/${IMAGE_NAME} .
}

ssh-keygen -f id-${VM_BASE} -N '' >/dev/null

cp "${SCRIPT_DIR}/../terraform/main.tf" . || exit 1
tofu init -input=false >&2 || exit 1

printf 'image_name = "%s"\nnode_count = 2\n' \
    "${IMAGE_NAME}" >terraform.tfvars

echo -n "# Create VMs "
tofu apply -input=false -auto-approve >&2 || exit 1
echo "ok"

NODE_IPS=$(tofu output -json node_ips) || exit 3
NODE_IP=$(jq -er '.[0]' <<<"${NODE_IPS}") || exit 3

umask 077
jq -en \
    --argjson ips "${NODE_IPS}" \
    --arg key "$(realpath id-${VM_BASE})" '
    {
      all: {
        vars: {
          ansible_user: "ubuntu",
          ansible_ssh_private_key_file: $key,
          ansible_ssh_common_args:
            "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes"
        },
        children: {
          k8s_init: {
            hosts: {
              "cni-test-0": {
                ansible_host: ($ips[0] // error("Missing node 0 address"))
              }
            }
          },
          k8s_join: {
            hosts: {
              "cni-test-1": {
                ansible_host: ($ips[1] // error("Missing node 1 address"))
              }
            }
          }
        }
      }
    }' >inventory.json || exit 3

ANSIBLE_LOG_PATH="$(pwd)/ansible.log" \
    ansible-playbook -i inventory.json \
    "${SCRIPT_DIR}/../ansible/site.yml" >&2 || exit 1

printf "\n# Node address:\nexport NODE_IP=%s\n" "${NODE_IP}"

popd >/dev/null

echo "# Use config:"
echo "export KUBECONFIG=`realpath ${WORK_DIR}/kubeconfig`"
