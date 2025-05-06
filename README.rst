pyroute2-cni
------------

A lab code to test Kubernetes integration with SRv6 / VRF

requirements
============

* kubernetes 1.31
* VMs: Ubuntu 24.04, one NIC

install
=======

.. code::

    kubectl apply -f https://raw.githubusercontent.com/svinota/pyroute2-cni/refs/heads/main/kubernetes/pyroute2-cni.yaml

maintenance info
================

see also `config['plan9']['port']`

any node can be used, all the info is replicated

.. warning::
   No recovery is pushed in the repo at the moment!

.. code::

   9p -a {node_ip}:8149 read allocated          # → allocated addresses
   9p -a {node_ip}:8149 read graph | display    # → topology map as SVG

configuration
=============

.. warning::
   Please notice that at the lab stage configuration options format
   may change daily.

**Namespace labels**

.. code::

    apiVersion: v1
    kind: Namespace
    metadata:
      labels:
        kubernetes.io/metadata.name: test
        pyroute2.org/prefix: "10.1.0.0"
        pyroute2.org/prefixlen: "16"
        pyroute2.org/vrf: "1000"
        pyroute2.org/vxlan: "200"
      name: test

* prefix: the prefix to use in the namespace
* prefixlen: the network mask bits
* vrf: the VRF to use for the namespace; see also `End.DT4 vrftable`;
  → creates interface `vrf-{int}` in the host netns
* vxlan: VXLAN id of the transport between nodes;
  → creates interface `vxlan-{int}` in the host netns


**Pod labels**

To be delivered soon

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

        [plan9]
        port = 8149

        [mdns]
        service = _9p2r._tcp.local.
