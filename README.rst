pyroute2-cni
------------

A lab project to test Kubernetes integration with EVPN-VXLAN / SRv6 / VRF

Requirements
============

* Kubernetes >= 1.31
* VM: Ubuntu 24.04 with one NIC
* VRF kernel module

Install
=======

Standard Kubernetes install.

.. code::

    curl -fsSL https://raw.githubusercontent.com/svinota/pyroute2-cni/refs/heads/main/kubernetes/install.sh | bash

This waits for the CRD to become established before applying the namespace,
RBAC, ConfigMap, and DaemonSet.

Talos install. When using Talos, it is important to guard `nodeIP` with
`validSubnets`, otherwise kubelet will interfere with CNI bridges:

.. code::

    #
    # controlplane.yaml
    #
    kubelet:
        nodeIP:
            validSubnets:
                - 192.168.124.0/24
    cluster:
        ...
        controlPlane:
            endpoint: https://192.168.124.37:6443
        ...
        network:
            ...
            cni:
                name: custom
                urls:
                    - https://github.com/svinota/pyroute2-cni/raw/refs/heads/main/kubernetes/crd.yaml
                    - https://github.com/svinota/pyroute2-cni/raw/refs/heads/main/kubernetes/namespace.yaml
                    - https://github.com/svinota/pyroute2-cni/raw/refs/heads/main/kubernetes/rbac.yaml
                    - https://github.com/svinota/pyroute2-cni/raw/refs/heads/main/kubernetes/config.yaml
                    - https://github.com/svinota/pyroute2-cni/raw/refs/heads/main/kubernetes/daemonset.yaml


Maintenance
===========

Allocated IP blocks:

.. code::

    $ kubectl get ipblocks.ipam.pyroute2.org
    NAME                                   CIDR              NODE    VRF    VNI    ALLOCATED   CAPACITY
    k8s02-vrf1024-vx5500-10-244-0-64-26    10.244.0.64/26    k8s02   1024   5500   1           62
    k8s02-vrf4005-vx4005-192-168-0-64-26   192.168.0.64/26   k8s02   4005   4005   1           62
    k8s02-vrf42-vx42-10-244-0-64-26        10.244.0.64/26    k8s02   42     42     14          62
    k8s03-vrf1024-vx5500-10-244-0-0-26     10.244.0.0/26     k8s03   1024   5500   5           62
    k8s03-vrf4004-vx4004-172-16-12-0-26    172.16.12.0/26    k8s03   4004   4004   2           62
    k8s03-vrf4005-vx4005-192-168-0-0-26    192.168.0.0/26    k8s03   4005   4005   1           62
    k8s03-vrf42-vx42-10-244-0-0-26         10.244.0.0/26     k8s03   42     42     10          62

Access FRR shell:

.. code::

    $ kubectl -n pyroute2-cni exec -ti {{pod-name}} -c pyroute2-frr -- vtysh

Useful vtysh commands:

.. code::

    # show bgp l2vpn evpn summary
    # show bgp l2vpn evpn route
    # show evpn mac vni all
    # show ip route vrf {{vrf-name}}

Configuration
=============

.. warning::
   At this stage breaking changes in the configuration might occur.

**Node annotations**

.. code::

    apiVersion: v1
    kind: Node
    metadata:
      annotations:
        ...
        pyroute2.org/rr: "192.168.124.1;192.168.124.2"
      name: k8s02

* rr: only used if ``config['bgp']['rr_mode'] == 'node-annotation'`

**Namespace annotations**

.. code::

    apiVersion: v1
    kind: Namespace
    metadata:
      annotations:
        ...
        pyroute2.org/prefix: "10.1.0.0"
        pyroute2.org/prefixlen: "16"
        pyroute2.org/vrf: "1000"
        pyroute2.org/vxlan: "200"
      name: test

* prefix: the prefix to use in the namespace
* prefixlen: the network mask bits
* vrf: the VRF to use for the namespace; see also ``End.DT4 vrf_table``;
  → creates interface ``vrf-{int}`` in the host netns
* vxlan: VXLAN id of the transport between nodes;
  → creates interface ``vxlan-{int}`` in the host netns


**ConfigMap**

.. code::

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: server-config
      namespace: pyroute2-cni
    data:
      server.ini: |
        [api]
        socket_path_api = /var/run/pyroute2/api
        socket_path_fd = /var/run/pyroute2/fdpass

        [network]
        host_if = enp1s0

        [default]
        prefix = 10.244.0.0
        prefixlen = 16
        vxlan = 42
        vrf = 42

        [bgp]
        # control-plane: deploy internal RRs
        # node-annotation: use an external RR, specified per node
        rr_mode = control-plane

        [plan9]
        port = 8149
