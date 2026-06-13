pyroute2-cni
------------

A rather simple CNI with EVPN-VXLAN / VRF support

Requirements
============

* Kubernetes 1.31+
* Ubuntu 24.04+ or Talos 1.13.0+
* Linux VRF kernel module

Install
=======

Standard Kubernetes install.

.. code::

    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/crds/0.1/
    kubectl wait --for=condition=Established crd/ipblocks.ipam.pyroute2.org
    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/releases/0.1.0/


This waits for the CRD to become established before applying the namespace,
RBAC, ConfigMap, and DaemonSet.

Talos install. When using Talos, it is important to guard `nodeIP` with
`validSubnets`; otherwise, kubelet will interfere with CNI bridges:

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

    kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh

Useful vtysh commands:

.. code::

    show bgp l2vpn evpn summary
    show bgp l2vpn evpn route type 5
    show ip route vrf {{vrf-name}}

Configuration
=============

**VRFNodeConfig**

If a CNI process doesn't find a corresponding `VRFNodeConfig`, it defaults
to the interface used for the default route and to its primary address.

Otherwise `VRFNodeConfig` helps to configure these parameters on per-node
basis:

.. code::

    apiVersion: cni.pyroute2.org/v1alpha1
    kind: VRFNodeConfig
    metadata:
      name: k8s02-vrnc
    spec:
      nodeRef:
        name: k8s02
      routerId: 192.168.124.2
      routeReflectors:
        - 192.168.124.1
      interfaces:
        - name: eth1
          local: 192.168.124.2

* nodeRef.name: target node name
* routerId: preferred router ID for the node
* routeReflectors: (optional) BGP route reflector peers for the node
* interfaces: node interfaces and their preferred local addresses

If no `routeReflectors` are given, then the CNI builds a BGP mesh in
the cluster.

**VRFDomain**

If there is no `VRFDomain` CR defined, CNI creates a default one.

.. code::

    apiVersion: cni.pyroute2.org/v1alpha1
    kind: VRFDomain
    metadata:
      name: vrf-200
    spec:
      vrf: 200
      table: 200
      prefix: 10.1.0.0
      prefixlen: 16
      ipblocklen: 26
      attachments:
        - type: l3vni
          vni: 200

* vrf: VRF id
* table: routing table id
* prefix: pod network prefix
* prefixlen: pod network prefix length
* ipblocklen: IPBlock sub-prefix length
* attachments: VNI attachments deployed in the VRF

By default, CNI creates the service VRF-42 with one `l3vni` attachment.

Available attachment types:

* `l2vni`: stretches a layer 2 switching domain across the cluster
* `l3vni`: builds a routing domain and uses node-specific subranges

If a VRF has multiple attachments, `l2vni` is preferred for attaching
pods, while `l3vni` can be used to integrate with external infrastructure.

**VRFDomainBinding**

`VRFDomainBinding` CR is cluster-scoped. It maps a Kubernetes namespace to a
cluster-scoped `VRFDomain` resource. `VRFDomainBindings` are managed by the CNI,
so no manual setup is needed.

.. code::

    apiVersion: cni.pyroute2.org/v1alpha1
    kind: VRFDomainBinding
    metadata:
      name: test02-vrf-200
    spec:
      namespaceRef:
        name: test02
      vrfDomainRef:
        name: vrf-200

* namespaceRef.name: target namespace name
* vrfDomainRef.name: target `VRFDomain` name

**ConfigMap**

The values in `[default]` section help to define the default `VRFDomain`,
if needed.

.. code::

    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: server-config
      namespace: pyroute2-cni
    data:
      server.ini: |
        [default]
        vrf = 42
        prefix = 10.244.0.0
        prefixlen = 16
        ipblocklen = 26
        system_vrf_type = l3vni

        [logging]
        level = info

Monitoring
==========

The DaemonSet exposes `/livez`, `/readyz`, and `/metrics` on port `24800`.
