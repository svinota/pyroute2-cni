#!/bin/bash

export LIBVIRT_DEFAULT_URI=qemu:///system

VM_BASE="cni-test"
WORK_DIR="vm-test"

function vm_destroy() {
    VM_IDX="$1"
    VM_NAME="${VM_BASE}-${VM_IDX}"
    virsh destroy ${VM_NAME} >/dev/null 2>&1
    virsh undefine ${VM_NAME} >/dev/null 2>&1
}

for i in 0 1; do {
    vm_destroy $i
} done

rm -rf ${WORK_DIR}
rm -f env.sh
