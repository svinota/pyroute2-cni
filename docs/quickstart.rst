.. quickstart:

Quickstart Guide
================

In this guide, we will:

#. install the CNI in a fresh Kubernetes cluster
#. configure nodes to use external route reflectors
#. create a tenant VRF
#. announce a prefix from the provider network to the VRF

This quickstart walks through the full path from a fresh test cluster to a
working tenant VRF with BGP reachability. It is intended to show both the
minimum setup and the expected end state.

Contents
--------

* :ref:`quickstart-prerequisites`
* :ref:`quickstart-install-cni`
* :ref:`quickstart-list-crds`
* :ref:`quickstart-access-vtysh`
* :ref:`quickstart-route-reflectors`
* :ref:`quickstart-tenant-vrf`
* :ref:`quickstart-inject-routes`

Components involved
-------------------

.. list-table::
   :header-rows: 1

   * - Component
     - Role
     - Where it runs
     - Introduced in this guide
   * - CNI plugin
     - Reconciles networking state and configures FRR
     - In the `pyroute2-cni` container
     - :ref:`quickstart-install-cni`
   * - FRR container
     - Runs BGP and EVPN control-plane services
     - In the `pyroute2-frr` container
     - :ref:`quickstart-access-vtysh`
   * - Route reflector
     - Aggregates BGP sessions for the cluster
     - Outside the Kubernetes node
     - :ref:`quickstart-route-reflectors`
   * - `VRFDomain`
     - Defines the tenant VRF template and address pool
     - Cluster-scoped CRD
     - :ref:`quickstart-list-crds`
   * - `IPBlock`
     - Represents a node-local allocation from the shared prefix
     - Cluster-scoped CRD
     - :ref:`quickstart-list-crds`
   * - `VRFNodeConfig`
     - Binds a node to the BGP setup and local interface
     - Cluster-scoped CRD
     - :ref:`quickstart-route-reflectors`
   * - Tenant workload
     - Set of pods and services representing the tenant's cloud-native workload
     - In the tenant namespace
     - :ref:`quickstart-tenant-vrf`

.. _quickstart-prerequisites:

Prerequisites
-------------

If you do not have a fresh Kubernetes cluster available, you can use
the test script from the `pyroute2-cni` CI to start and set up an
Ubuntu VM and a test cluster.

On the host system, you should have the following:

Utilities:

* ssh-keygen
* curl
* virsh
* cloud-localds
* qemu-img
* virt-install

Services and resources:

* working libvirt / KVM
* 30 GB disk space for the VM
* 4 GB memory for the VM
* internet access

Install the VM
~~~~~~~~~~~~~~

This step bootstraps the example environment used throughout the rest of the
guide. When it succeeds, you should have a ready-to-use test cluster, SSH
credentials, and a kubeconfig under `vm-test`.

.. code-block::

    # clone the repo
    git clone https://github.com/svinota/pyroute2-cni.git && cd pyroute2-cni

    # install the VM
    ./tests/test_install/scripts/create-ubuntu-vm.sh 24 | tee env.sh

    # setup env
    . env.sh

The script takes several minutes to run: it downloads the VM base image,
starts the VM, and runs scripts there to set up the system and install
Kubernetes. The output of the script is itself usable as a shell script: it
exports two variables, `NODE_IP` and `KUBECONFIG`. You can simply source it
with `. env.sh`, and then use `kubectl` against the test cluster.

After this step, you should have an Ubuntu 24.04 VM with Kubernetes 1.36
installed, but without any CNI. Installation logs, kubeconfig, and SSH keys
are located in `vm-test` directory. Also, the script creates a `tmp`
directory where it downloads the VM base image; if you do not remove it, it
will be used as the image cache.

You can use the SSH keys to access the VM shell:

.. code-block::

    $ . env.sh
    $ ssh -i vm-test/id-cni-test ubuntu@${NODE_IP}
    ...
    ubuntu@cni-test:~$

Or use `kubectl` to access the Kubernetes API:

.. code-block::

    $ . env.sh
    $ kubectl get nodes
    NAME       STATUS     ROLES           AGE    VERSION
    cni-test   NotReady   control-plane   4m7s   v1.36.2

    $ kubectl get pods -A
    NAMESPACE     NAME                               READY   STATUS    RESTARTS   AGE
    kube-system   coredns-589f44dc88-m8m5n           0/1     Pending   0          4m11s
    kube-system   coredns-589f44dc88-t9ztr           0/1     Pending   0          4m11s
    kube-system   etcd-cni-test                      1/1     Running   0          4m17s
    kube-system   kube-apiserver-cni-test            1/1     Running   0          4m17s
    kube-system   kube-controller-manager-cni-test   1/1     Running   0          4m17s
    kube-system   kube-proxy-nwnzp                   1/1     Running   0          4m11s
    kube-system   kube-scheduler-cni-test            1/1     Running   0          4m17s

As you can see, the `coredns` pods are in the `Pending` state; this is because
there is no CNI installed yet.

.. _quickstart-install-cni:

Install CNI
-----------

These manifests install the CRDs first so the API objects exist before the
controller starts reconciling them, and then install the CNI itself:

.. code-block::

    # install required CRDs
    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/crds/0.1/

    # wait for the CRD to become established
    kubectl wait --for=condition=Established crd/ipblocks.ipam.pyroute2.org

    # install the CNI namespace, RBAC, configs and other manifests
    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/releases/0.1.0/

    # wait for the CNI to start
    kubectl -n pyroute2-cni wait --for=condition=Ready pods --all

.. _quickstart-list-crds:

List the CRDs
-------------

By default, the CNI creates a `VRFDomain` instance with values from the
`server-config` ConfigMap.  `VRFDomain` is the cluster-wide default VRF
template. It defines the base prefix and the tenant allocation layout:

.. code-block::

    $ kubectl get vrfdomains -o yaml
    apiVersion: v1
    items:
    - apiVersion: cni.pyroute2.org/v1alpha1
      kind: VRFDomain
      metadata:
        name: vrf-42
        ...
      spec:
        attachments:
        - port: 4789
          type: l3vni
          vni: 42
        ipblocklen: 26
        prefix: 10.244.0.0
        prefixlen: 16
        table: 42
        vrf: 42
    kind: List
    metadata:
      resourceVersion: ""

`ipblocklen` is the prefix length used to divide the common prefix (`prefix`,
`prefixlen`) into subranges.

`IPBlock` is the per-node allocation created from the shared prefix. The CNI
automatically allocates `IPBlocks` for the subranges and announces them for
the node they are set up on:

.. code-block::

    $ kubectl get ipblocks -o yaml
    apiVersion: v1
    items:
    - apiVersion: ipam.pyroute2.org/v1alpha1
      kind: IPBlock
      metadata:
        name: vrf-42-10-244-0-0-26
        ...
      spec:
        cidr: 10.244.0.0/26
        nodeName: cni-test
        vrfTable: 42
      status:
        allocated: 3
        allocations:
          10.244.0.1: gateway
          10.244.0.2: 9c9567d8-fd38-45ef-956c-b7624d667b85
          10.244.0.3: 20bad6ec-5a5f-4801-97d7-bb2243eb2357
        capacity: 62
    kind: List
    metadata:
      resourceVersion: ""

.. _quickstart-access-vtysh:

Access vtysh
------------

Every CNI pod has its own FRR instance, and you can access the integrated
FRR shell `vtysh`, which is the quickest way to inspect the control-plane
state on the node.

.. code-block::

    $ kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh

    Hello, this is FRRouting (version 8.4_git).
    Copyright 1996-2005 Kunihiro Ishiguro, et al.

    cni-test#

Here you can check VRF, BGP status, routes and much more:

.. code-block::

    cni-test# show evpn vni
    VNI        Type VxLAN IF              # MACs   # ARPs   # Remote VTEPs  Tenant VRF
    42         L3   l3vx-42               0        0        n/a             vrf-42

There are no neighbors in a single-node cluster so far:

.. code-block::

    cni-test# show bgp summary
    % No BGP neighbors found in VRF default

But if you have a cluster with multiple nodes, then you'll see the BGP mesh
by default.

.. _quickstart-route-reflectors:

Set up Route Reflectors
-----------------------

BGP mesh is simple, but not scalable. To set up larger networks, it is
better to use route reflectors to aggregate the BGP sessions. It is better to
have two or more RRs, but for testing purposes we will set up one.

.. note:: `RR` here means route reflector.

First, adjust the example config files. Set the correct addresses for both the
RR and the test node. In our example, the node has address `192.168.124.54`,
and the host is `192.168.124.1`:

.. code-block::

    $ vim ./examples/frr/frr.conf  # add your peers

Once the configs are fixed, start FRR in a container:

.. code-block::

    # Ubuntu / docker run:
    docker run --rm -it -v ./examples/frr/:/etc/frr --privileged --network host --name frr ghcr.io/svinota/pyroute2-frr:0.0.7

    # Fedora / podman run:
    sudo podman run --rm -it -v ./examples/frr/:/etc/frr:Z --privileged --network host --name frr ghcr.io/svinota/pyroute2-frr:0.0.7

Alternatively, you can use your existing BGP routers, but then adjust
your setup accordingly in order to inject prefixes.

Once the container has started, you can check readiness from the host system:

.. code-block::

    $ curl http://localhost:24801/readyz
    ok

Now it's time to configure Kubernetes nodes to use our RR. Adjust and apply
the VRFNodeConfig from examples:

.. warning::  Use your node IP address for `routerId` and `interfaces[].local`,
    and place the RR address in the `routeReflectors[]` list.

.. code-block::

    $ cat ./examples/vrfnodeconfig.yaml
    ---
    apiVersion: cni.pyroute2.org/v1alpha1
    kind: VRFNodeConfig
    metadata:
      name: cni-test-vrnc
    spec:
      nodeRef:
        name: cni-test
      routerId: 192.168.124.54
      routeReflectors:
        - 192.168.124.1
      interfaces:
        - name: enp1s0
          local: 192.168.124.54
 
The `VRFNodeConfig` declares the local interface that participates in the
BGP setup. Route reflectors are optional; if none are specified, the CNI
builds a BGP mesh within the cluster.

.. code-block::

    $ kubectl create -f ./examples/vrfnodeconfig.yaml
    vrfnodeconfig.cni.pyroute2.org/cni-test-vrnc created

    $ kubectl get vrnc
    NAME            ROUTERID         ROUTEREFLECTORS   INTERFACES   ACCEPTED   READY
    cni-test-vrnc   192.168.124.54   1                 1            true       true

You can see a short summary of the node config: how many interfaces are
defined there, how many route reflectors it is using, and whether it is
applied to the system.

Let's check the BGP summary on the node:

.. code-block::

    $ kubectl -n pyroute2-cni exec daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh -c "show bgp summary"

    IPv4 Unicast Summary (VRF default):
    BGP router identifier 192.168.124.54, local AS number 65000 vrf-id 0
    BGP table version 0
    RIB entries 1, using 192 bytes of memory
    Peers 1, using 717 KiB of memory
    Peer groups 1, using 64 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    192.168.124.1   4      65000         5         5        0    0    0 00:01:44        NoNeg    NoNeg N/A

    Total number of neighbors 1

    L2VPN EVPN Summary (VRF default):
    BGP router identifier 192.168.124.54, local AS number 65000 vrf-id 0
    BGP table version 0
    RIB entries 1, using 192 bytes of memory
    Peers 1, using 717 KiB of memory
    Peer groups 1, using 64 bytes of memory

    Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    192.168.124.1   4      65000         5         5        0    0    0 00:01:44            0        1 N/A

    Total number of neighbors 1

Here we see that the node has connected to the RR. We are halfway
to success.

.. _quickstart-tenant-vrf:

Set up tenant VRF
-----------------

Let's create a tenant VRF and bind a Kubernetes namespace to it. This is the
point where the tenant abstraction becomes visible in the cluster state.
The `VRFDomain` CRD describes the VRF, while `VRFDomainBinding` instructs the
CNI to attach pods in a namespace to a specific VRF:

.. code-block::

    $ kubectl create -f ./examples/vrfdomain.yaml
    vrfdomain.cni.pyroute2.org/vrf-200 created
    vrfdomainbinding.cni.pyroute2.org/vrf-200 created

Deploy the tenant workload:

.. code-block::

    $ kubectl apply -f examples/tenant.yaml
    namespace/test-namespace created
    deployment.apps/test-deployment created
    service/test-service created

Check that L3 VRF `vrf-200` has appeared in the CNI BGP shell:

.. code-block::

    $ kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh
    ...
    cni-test# show evpn vni
    VNI        Type VxLAN IF              # MACs   # ARPs   # Remote VTEPs  Tenant VRF
    50200      L3   l3vx-50200            1        1        n/a             vrf-200
    42         L3   l3vx-42               0        0        n/a             vrf-42
    cni-test# 

.. _quickstart-inject-routes:

Inject routes
-------------

So far we have no working VRFs on the RR side, only FRR config for it. Note
`Tenant VRF: Unknown`. This confirms that the route reflector has the BGP
configuration, but the VRF itself still needs to be created on the host.

.. code-block::

    $ sudo podman exec -ti frr vtysh
    ...
    rr-01# show evpn vni
    VNI        Type VxLAN IF              # MACs   # ARPs   # Remote VTEPs  Tenant VRF
    50200      L3   None                  0        0        n/a             Unknown

First, start the VRF. The script will create `bridge`, `vxlan`, and `vrf`
interfaces, link them in the way FRR expects, set them up, and inject a route
in the VRF.

.. code-block::

    $ ./examples/frr/create-vrf.sh setup

Then check FRR, look at the `Tenant VRF` field:

.. code-block::

    $ sudo podman exec -ti frr vtysh
    ...
    rr-01# show evpn vni
    VNI        Type VxLAN IF              # MACs   # ARPs   # Remote VTEPs  Tenant VRF
    50200      L3   vxlan-200             1        1        n/a             vrf-200


Check the routes. The script `create-vrf.sh` injects the `1.2.3.0/24` prefix.
This is the route that the Kubernetes side should learn and later expose
inside the tenant VRF.

.. code-block::

    $ sudo podman exec -ti frr vtysh
    ...
    rr-01# show bgp l2vpn evpn route
    BGP table version is 3, local router ID is 192.168.124.1
    Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
    Origin codes: i - IGP, e - EGP, ? - incomplete
    EVPN type-1 prefix: [1]:[EthTag]:[ESI]:[IPlen]:[VTEP-IP]:[Frag-id]
    EVPN type-2 prefix: [2]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
    EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]
    EVPN type-4 prefix: [4]:[ESI]:[IPlen]:[OrigIP]
    EVPN type-5 prefix: [5]:[EthTag]:[IPlen]:[IP]

       Network          Next Hop            Metric LocPrf Weight Path
                        Extended Community
    Route Distinguisher: 0.0.0.0:2
    *> [5]:[0]:[24]:[1.2.3.0]
                        192.168.124.1            0         32768 ?
                        ET:8 RT:65000:200 Rmac:c6:23:4a:d0:c4:f3
    Route Distinguisher: 10.150.0.1:3
    *>i[5]:[0]:[26]:[10.150.0.0]
                        192.168.124.54           0    100      0 ?
                        RT:65000:200 ET:8 Rmac:a2:57:0e:2b:e5:d9
    Route Distinguisher: 10.244.0.1:2
    *>i[5]:[0]:[26]:[10.244.0.0]
                        192.168.124.54           0    100      0 ?
                        RT:65000:42 ET:8 Rmac:16:70:37:ba:22:d9

    Displayed 3 prefixes (3 paths)


Here we see the route. But let's check it on the Kubernetes side:

.. code-block::

    $ kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-frr -- vtysh
    ...
    cni-test# show ip route vrf vrf-200
    Codes: K - kernel route, C - connected, S - static, R - RIP,
           O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
           T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
           f - OpenFabric,
           > - selected route, * - FIB route, q - queued, r - rejected, b - backup
           t - trapped, o - offload failure

    VRF vrf-200:
    B>* 1.2.3.0/24 [200/0] via 192.168.124.1, l3br-200 onlink, weight 1, 00:04:03
    C>* 10.150.0.0/26 is directly connected, l3br-200, 00:09:12


Now `1.2.3.0/24` is reachable from the Kubernetes pods in the tenant VRF.

Congrats! The integration is complete.

Troubleshooting
---------------

* a VM starts to fail: all the logs are in the `vm-test` directory; once
  done with the debugging, feel free to clean up the workspace with eventually
  started VM using `make clean`; then you can try again

* `bgpd` and/or `zebra` don't start on the RR side in the container: in
  some setups you have to start them under root; also LSM/AppArmor can
  affect the signals delivery between FRR daemons, you can see that in `dmesg`

* `podman` starts the container, but doesn't mount the `/etc/frr` directory:
  don't forget `:Z` in the volume mount argument, if you are using SELinux.

* RR and VM don't see each other: if you are using multiple libvirt networks,
  make sure that the RR address is the bridge address for the corresponding
  network.
