#!/bin/bash

export LIBVIRT_DEFAULT_URI=qemu:///system

VM_NAME="cni-test"
WORK_DIR="vm-test"

virsh destroy ${VM_NAME} >/dev/null 2>&1
virsh undefine ${VM_NAME} >/dev/null 2>&1
rm -rf ${WORK_DIR}
rm -f env.sh
