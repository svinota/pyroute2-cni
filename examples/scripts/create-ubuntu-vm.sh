#!/bin/bash

LIBVIRT_DEFAULT_URI=qemu:///system
VM_NAME="cni-test"
IMAGE_NAME="ubuntu-25.10-server-cloudimg-amd64.img"
IMAGE_BASE="https://cloud-images.ubuntu.com/releases/questing/release/"
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
WORK_DIR="vm-test"

mkdir -p ${WORK_DIR}
pushd ${WORK_DIR}


# sanity check
ls -1 |\
    grep -v ${IMAGE_NAME} |\
    wc -l |\
    grep ^0 >/dev/null || { echo "Start in an empty directory"; exit 1; }

for i in ssh-keygen virsh cloud-localds qemu-img curl virt-install; do {
    echo -n "Check $i ... "
    which $i >/dev/null 2>&1 || { echo "required $i missing"; exit 2; }
    echo "ok"
} done

[ -f "${IMAGE_NAME}" ] || {
    echo "Download Ubuntu cloud image"
    curl -Lo ${IMAGE_NAME} ${IMAGE_BASE}/${IMAGE_NAME}
}

ssh-keygen -f id-${VM_NAME} -N ''

echo "Create cloud-init"
cat <<EOF >user-data
#cloud-config
hostname: ${VM_NAME}

users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - `cat id-${VM_NAME}.pub`

package_update: true
packages:
  - curl
EOF

cat <<EOF >meta-data

instance-id: ${VM_NAME}-01
local-hostname: ${VM_NAME}
EOF

cloud-localds seed.iso user-data meta-data

echo "Create VM image"
qemu-img create -f qcow2 -b ${IMAGE_NAME} -F qcow2 ${VM_NAME}.qcow2 30G

echo "Create VM"
virt-install \
    --name ${VM_NAME} \
    --memory 4096 \
    --vcpus 2 \
    --disk path=${VM_NAME}.qcow2,format=qcow2,bus=virtio \
    --disk path=seed.iso,device=cdrom \
    --network network=default \
    --import \
    --noautoconsole \
    --os-variant ubuntu25.10

echo -n "Waiting for IP address "
for i in `seq 100`; do {
    NODE_IP=`virsh domifaddr cni-test 2>/dev/null | awk '/ipv4/ {print gensub(/\/.+/, "", "g", $4)}'`
    [ -z "${NODE_IP}" ] || break
    echo -n .
    sleep 1
} done

[ -z "${NODE_IP}" ] && { echo "Could not get node IP"; exit 3; }

echo -e "\nNode address: ${NODE_IP}"

echo -n "Waiting for SSH "
for i in `seq 1 100`; do {
    ssh -o StrictHostKeyChecking=no -i id-${VM_NAME} ubuntu@${NODE_IP} uname -a && break
    echo .
    sleep 1
} done

scp -i id-${VM_NAME} ${SCRIPT_DIR}/k8s_prepare.sh ubuntu@${NODE_IP}:./
scp -i id-${VM_NAME} ${SCRIPT_DIR}/k8s_init.sh ubuntu@${NODE_IP}:./
ssh -i id-${VM_NAME} ubuntu@${NODE_IP} sudo bash ./k8s_prepare.sh
ssh -i id-${VM_NAME} ubuntu@${NODE_IP} sudo bash ./k8s_init.sh
ssh -i id-${VM_NAME} ubuntu@${NODE_IP} sudo cat /etc/kubernetes/admin.conf >kubeconfig

popd

echo "Use KUBECONFIG=`realpath ${WORK_DIR}/kubeconfig`"
