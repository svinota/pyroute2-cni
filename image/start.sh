#!/bin/sh

cp 05-chain.conflist /host/etc/cni/net.d/
cp pyroute2-cni-plugin /host/opt/cni/bin/
exec /usr/local/bin/pyroute2-cni
