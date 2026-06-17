Introduction
------------

pyroute2-cni is a Kubernetes networking layer for service provider and
enterprise environments built around VRFs and BGP-routed network fabrics.

* Documentation Home: https://cni.pyroute2.org/
* Project Sources: https://github.com/svinota/pyroute2-cni

Requirements
============

* Kubernetes 1.31+
* Ubuntu 24.04 or Talos 1.13.0+
* vrf support
* nftables support

Install
=======

Standard Kubernetes install
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code::

    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/crds/0.1/
    kubectl wait --for=condition=Established crd/ipblocks.ipam.pyroute2.org
    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/releases/0.1.0/


This waits for the CRD to become established before applying the namespace,
RBAC, ConfigMap, and DaemonSet.

Talos install
~~~~~~~~~~~~~

When using Talos, it is important to restrict `nodeIP` with `validSubnets`;
otherwise, kubelet will interfere with CNI bridges. Set `validSubnets` to the
network used by your nodes.

.. code::

    #
    # controlplane.yaml
    #
    kubelet:
        ...
        nodeIP:
            validSubnets:
                - 192.168.124.0/24   # the network used by the nodes
    cluster:
        ...
        network:
            ...
            cni:
                name: none

After running `talosctl ... health`, continue with the standard Kubernetes
install from the section above and run `kubectl apply -k ...`

Maintenance
===========

Allocated IP blocks:

.. code::

    $ kubectl get ipblocks.ipam.pyroute2.org
    NAME                      CIDR              NODE    VRF   ALLOCATED   CAPACITY
    vrf-200-10-150-0-0-26     10.150.0.0/26     k8s03   200   62          62
    vrf-200-10-150-0-128-26   10.150.0.128/26   k8s03   200   41          62
    vrf-200-10-150-0-192-26   10.150.0.192/26   k8s02   200   41          62
    vrf-200-10-150-0-64-26    10.150.0.64/26    k8s02   200   62          62
    vrf-42-10-244-0-0-26      10.244.0.0/26     k8s03   42    4           62
    vrf-42-10-244-0-64-26     10.244.0.64/26    k8s02   42    4           62

Access FRR shell:

.. code::

    kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh

It might be handy to add it as an alias in `.bashrc`.

Useful vtysh commands:

.. code::

    show bgp l2vpn evpn summary
    show bgp l2vpn evpn route type 5
    show ip route vrf {{vrf-name}}

Configuration
=============

The default settings start the CNI with full-mesh BGP and one system VRF,
using the interfaces of the default route as VTEPs.

This should be enough to run a medium-sized cluster in most typical setups.

Large clusters work better with route reflectors, so you must set some up
before deploying the CNI and use `VRFNodeConfigs` to instruct the CNI to use
them.

If you want to customize the CNI, use the following CRDs:

**VRFNodeConfig**

If a CNI process doesn't find a corresponding `VRFNodeConfig`, it defaults
to the interface used for the default route and its primary address.

Otherwise, `VRFNodeConfig` helps configure these parameters on a per-node
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

If no `routeReflectors` are given, the CNI builds a BGP mesh in the cluster.

**VRFDomain**

If there are no `VRFDomain` CRs defined, the CNI creates a default one
(`vrf-42`) with one `l3vni` attachment.

Here is an example `VRFDomain` you can use to create your own:

.. code::

    apiVersion: cni.pyroute2.org/v1alpha1
    kind: VRFDomain
    metadata:
      name: vrf-200
    spec:
      vrf: 200
      table: 10200
      prefix: 10.1.0.0
      prefixlen: 16
      ipblocklen: 26
      attachments:
        - type: l3vni
          vni: 60200
          port: 4789

* vrf: VRF id
* table: routing table id
* prefix: pod network prefix
* prefixlen: pod network prefix length
* ipblocklen: IPBlock sub-prefix length
* attachments: VNI attachments deployed in the VRF

Available attachment types:

* `l2vni`: stretches a layer 2 switching domain across the cluster
* `l3vni`: builds a routing domain and uses node-specific subranges

If a VRF has multiple attachments, `l2vni` is preferred for attaching
pods, while `l3vni` can be used to integrate with external infrastructure.

**VRFDomainBinding**

`VRFDomainBinding` CRs are cluster-scoped. They map Kubernetes namespaces to
cluster-scoped `VRFDomain` resources. If there is a `VRFDomainBinding` for a
namespace, then pods in this namespace will be attached to the corresponding
VRF when they are created.

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
 
**IPBlock**

The whole `VRFDomain` prefix is divided into `IPBlocks` in order to set up
routing for the pods. `IPBlock` CRs are created and managed by the CNI, so no
manual setup is needed. They describe the mapping of pods to IP addresses.
Every sub-range has a gateway address that is used to announce the sub-range
to neighbours.

**ConfigMap**

The values in the `[default]` section help define the default `VRFDomain`,
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
