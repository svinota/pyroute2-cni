#!/bin/bash

WORK_DIR="vm-test"

if [ -d "${WORK_DIR}" ]; then
    tofu -chdir="${WORK_DIR}" destroy \
        -input=false -auto-approve || exit 1
fi

rm -rf ${WORK_DIR}
rm -f env.sh
