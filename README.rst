pyroute2-cni
------------

A lab code to test Kubernetes integration with SRv6 / VRF

requirements
============

* kubernetes 1.31
* VMs: Ubuntu 24.04, one NIC
* modules preload: overlay, br_netfilter, vrf

install
=======

.. code::

    kubectl apply -f https://raw.githubusercontent.com/svinota/pyroute2-cni/refs/heads/main/kubernetes/namespace.yaml
    kubectl apply -f https://raw.githubusercontent.com/svinota/pyroute2-cni/refs/heads/main/kubernetes/daemonset.yaml

network
=======

* one vxlan
* one VRF
* hardcoded prefix 10.244.0.0/16

.. code::

    vrf:
        name: vrf0
        table: 1010

    vxlan:
        name: pr2-vxlan147
        link: enp1s0
        master: pr2-bridge

    bridge:
        name: pr2-bridge
        master: vrf0
        ports:
            - pr2-vxlan147
            - container veth ...
            - container veth ...
