#!/bin/bash


function setup() {
    sudo ip link add dev vrf-200 type vrf table 2100
    sudo ip link add dev br-200 type bridge
    sudo ip link add dev vxlan-200 type vxlan id 50200 dstport 4789 local 192.168.124.1 nolearning

    sudo ip link set dev vxlan-200 master br-200
    sudo ip link set dev br-200 master vrf-200

    sudo ip link set dev vxlan-200 up
    sudo ip link set dev br-200 up
    sudo ip link set dev vrf-200 up

    sudo ip route add 1.2.3.0/24 dev br-200 vrf vrf-200
}

function cleanup() {
    sudo ip link del dev vxlan-200
    sudo ip link del dev br-200
    sudo ip link del dev vrf-200
}

case "$1" in
    "setup")
        setup
        ;;
    "cleanup")
        cleanup
        ;;
    *)
        echo "Unknown command"
        ;;
esac
