#!/bin/bash

export LIBVIRT_DEFAULT_URI=qemu:///system

PLATFORM="$1"
TALOS_VERSION="v1.14.0"

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

[ "${PLATFORM}" = "talos" ] && {
    export IMAGE_NAME="talos-${TALOS_VERSION}-metal-amd64.iso"
    export IMAGE_BASE="https://github.com/siderolabs/talos/releases/download/${TALOS_VERSION}"
    IMAGE_DOWNLOAD_NAME="metal-amd64.iso"
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

TOOLS=(jq curl tofu)
if [ "${PLATFORM}" = "talos" ]; then
    TOOLS+=(kubectl)
else
    TOOLS+=(ssh-keygen ansible-playbook)
fi

for i in "${TOOLS[@]}"; do {
    echo -n "# Check $i ... "
    which $i >/dev/null 2>&1 || { echo "# required $i missing"; exit 2; }
    echo "ok"
} done

[ -f "../${TMP_DIR}/${IMAGE_NAME}" ] || {
    echo -n "# Download VM image ... "
    curl -fSsLo "../${TMP_DIR}/${IMAGE_NAME}" \
        "${IMAGE_BASE}/${IMAGE_DOWNLOAD_NAME:-${IMAGE_NAME}}" || exit 1
    echo "ok"
}

[ -f "${IMAGE_NAME}" ] || {
    cp ../${TMP_DIR}/${IMAGE_NAME} .
}

if [ "${PLATFORM}" != "talos" ]; then
    ssh-keygen -f id-${VM_BASE} -N '' >/dev/null
fi

umask 077
cp -r "${SCRIPT_DIR}/../terraform/"*.tf \
    "${SCRIPT_DIR}/../terraform/modules" . || exit 1
tofu init -input=false >&2 || exit 1

printf 'image_name = "%s"\nnode_count = 2\nplatform = "%s"\ntalos_version = "%s"\n' \
    "${IMAGE_NAME}" "${PLATFORM}" "${TALOS_VERSION}" >terraform.tfvars

echo -n "# Create VMs "
tofu apply -input=false -auto-approve >&2 || exit 1
echo "ok"

NODE_IPS=$(tofu output -json node_ips) || exit 3
NODE_IP=$(jq -er '.[0]' <<<"${NODE_IPS}") || exit 3

if [ "${PLATFORM}" = "talos" ]; then
    tofu output -raw kubeconfig >kubeconfig || exit 1
    tofu output -raw talosconfig >talosconfig || exit 1
    chmod 600 kubeconfig talosconfig

    REGISTERED=0
    for i in `seq 1 120`; do {
        if NODES=$(kubectl --kubeconfig ./kubeconfig \
            --request-timeout=10s get nodes -o json 2>/dev/null) &&
            jq -e '[.items[].metadata.name] | sort ==
                ["cni-test-0", "cni-test-1"]' \
                <<<"${NODES}" >/dev/null; then
            REGISTERED=1
            break
        fi
        sleep 2
    } done
    [ "${REGISTERED}" -eq 1 ] || {
        echo "# Expected Talos Kubernetes nodes did not register" >&2
        exit 1
    }

    printf 'export TALOSCONFIG=%q\n' "$(realpath talosconfig)"
else
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
fi

printf "\n# Node address:\nexport NODE_IP=%s\n" "${NODE_IP}"

popd >/dev/null

echo "# Use config:"
echo "export KUBECONFIG=`realpath ${WORK_DIR}/kubeconfig`"
