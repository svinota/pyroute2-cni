#!/bin/bash

export LIBVIRT_DEFAULT_URI=qemu:///system

[ "$1" = "24" ] && {
    export IMAGE_NAME="ubuntu-24.04-server-cloudimg-amd64.img"
    export IMAGE_BASE="https://cloud-images.ubuntu.com/releases/noble/release/"
} ||:

[ "$1" = "25" ] && {
    export IMAGE_NAME="ubuntu-25.10-server-cloudimg-amd64.img"
    export IMAGE_BASE="https://cloud-images.ubuntu.com/releases/questing/release/"
} ||:

[ "$1" = "26" ] && {
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

for i in ssh-keygen virsh cloud-localds qemu-img curl virt-install; do {
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

function start_vm() {
    VM_IDX="$1"
    VM_NAME="${VM_BASE}-${VM_IDX}"
    echo -n "# Create cloud-init "
    cat <<EOF >user-data
#cloud-config
hostname: ${VM_NAME}

users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - `cat id-${VM_BASE}.pub`

package_update: true
packages:
  - curl
EOF

cat <<EOF >meta-data

instance-id: ${VM_NAME}
local-hostname: ${VM_NAME}
EOF

    cloud-localds ${VM_NAME}-seed.iso user-data meta-data && echo "ok"

    echo -n "# Create VM image "
    qemu-img create -f qcow2 -b ${IMAGE_NAME} -F qcow2 ${VM_NAME}.qcow2 30G >/dev/null && echo "ok"

    echo -n "# Create VM "
    virt-install \
        --name ${VM_NAME} \
        --memory 4096 \
        --vcpus 2 \
        --disk path=${VM_NAME}.qcow2,format=qcow2,bus=virtio \
        --disk path=${VM_NAME}-seed.iso,device=cdrom \
        --network network=default \
        --import \
        --noautoconsole \
        --os-variant ubuntu25.10 >/dev/null && echo "ok"

    echo -n "# Waiting for IP address "
    for i in `seq 100`; do {
        NODE_IP=`virsh domifaddr ${VM_NAME} 2>/dev/null | awk '/ipv4/ {print gensub(/\/.+/, "", "g", $4)}'`
        [ -z "${NODE_IP}" ] || break
        echo -n .
        sleep 1
    } done

    [ -z "${NODE_IP}" ] && { echo "# Could not get node IP"; exit 3; }

    if [ -f "kubeconfig" ]; then {
       printf "\n"
    } else {
       printf "\n# Node address:\nexport NODE_IP=%s\n" ${NODE_IP}
    } fi

    ephemeral_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i id-${VM_BASE}"
    ephemeral_ssh="ssh ${ephemeral_opts} ubuntu@${NODE_IP} "
    ephemeral_scp="scp ${ephemeral_opts} "

    echo -n "# Waiting for SSH "
    for i in `seq 1 100`; do {
        ${ephemeral_ssh} uname -a >/dev/null 2>&1 && break
        echo -n "."
        sleep 1
    } done

    ${ephemeral_scp} ${SCRIPT_DIR}/k8s_prepare.sh ubuntu@${NODE_IP}:./ >/dev/null 2>&1
    ${ephemeral_scp} ${SCRIPT_DIR}/k8s_init.sh ubuntu@${NODE_IP}:./ >/dev/null 2>&1
    echo -en "\n# Prepare the system to run kubernetes ... "
    ${ephemeral_ssh} sudo bash ./k8s_prepare.sh >k8s_prepare.log 2>&1 && echo "ok"
    if [ -f "kubeconfig" ]; then {
        printf "# Join the cluster ... "
        ${ephemeral_ssh} sudo $(cat token) --control-plane --certificate-key $(cat cert) >>k8s_join.log 2>&1 && printf "ok\n"
    } else {
        printf "# Init the cluster ... "
        ${ephemeral_ssh} sudo bash ./k8s_init.sh >k8s_init.log 2>&1 && printf "ok\n"
        printf "# Fetch the token ... "
        ${ephemeral_ssh} sudo kubeadm token create --print-join-command --ttl 15m >token 2>/dev/null && printf "ok\n"
        printf "# Fetch the cert ... "
        ${ephemeral_ssh} sudo kubeadm init phase upload-certs --upload-certs 2>/dev/null | tail -1 >cert && printf "ok\n"
        printf "# Fetch kubeconfig ... "
        ${ephemeral_ssh} sudo cat /etc/kubernetes/admin.conf >kubeconfig 2>/dev/null && printf "ok\n"
    } fi
}

for i in 0 1; do {
    start_vm $i
} done

popd >/dev/null

echo "# Use config:"
echo "export KUBECONFIG=`realpath ${WORK_DIR}/kubeconfig`"
