.. architecture:

CNI architecture and protocols
==============================

Network topology
----------------

.. image:: _images/CNI-overview.svg
   :target: _images/CNI-overview.svg

Plugin
------

* `/opt/cni/bin/pyroute2-cni-plugin`
* a static binary that only forwards info to the server container

The plugin workflow:

1. executed by kubelet
2. get CNI JSON from `stdin`
3. get environment variables
4. parse the variables and open `CNI_NETNS` -> obtain an open FD
5. obtain a new request id from the server
6. send the FD to the server over `socket_path_fd`
7. send the CNI and env data to the server over `socket_path_api`
8. await the response
9. print the response to `stdout`

Server
------

Container: pyroute2-frr
~~~~~~~~~~~~~~~~~~~~~~~

* image: `ghcr.io/svinota/pyroute2-cni:{version}`
* runs FRR: zebra, staticd, bgpd
* runs EVPN-VXLAN controlplane
* exposes and monitors a UNIX socket to reload configuratuion

Container: pyroute2-cni
~~~~~~~~~~~~~~~~~~~~~~~

* image:  `ghcr.io/svinota/pyroute2-cni:{version}`
* uses the host network namespace
* exposes two UNIX sockets for the API and an HTTP readiness endpoint

The server workflow:

#. watch namespaces and VRF domain objects
#. reconcile periodic address-pool and firewall jobs
#. await request init
#. allocate and respond with a request id
#. collect netns FD, CNI data and env variables from all the communication sockets
#. set up the container network
#. send the CNI response to the plugin

.. image:: _images/CNI-plugin-flow.svg
   :target: _images/CNI-plugin-flow.svg

Controller flow
---------------

The server keeps node state synchronised with background controllers:

* `NamespaceController` watches namespaces and triggers namespace lifecycle hooks.
* `VRFController` watches `VRFDomain` objects, creates or removes VRFs and VXLAN-backed bridges, and reconciles firewall rules.

Also it has managers:

* `AddressPool` handles allocation, reconciliation, and garbage collection of pod address blocks.
* `FirewallManager` owns the nftables setup and per-VRF NAT and marking rules.
