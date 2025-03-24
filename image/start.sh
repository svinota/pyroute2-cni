#!/bin/sh

cp 05-chain.conflist /host/etc/cni/net.d/
cp pyroute2-cni-plugin /host/opt/cni/bin/
python pyroute2-cni-gateway/main.py
