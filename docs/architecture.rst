.. architecture:

pyroute2 CNI architecture and protocols
=======================================

Network topology
----------------

.. aafig::
   :scale: 80
   :textual:

    +------------+           +------------+
    |   enp1s0   |           |  `vrf-X`   |
    +------------+           +------------+
           ^                        ^
           | `link`                 | `master`
           o                        o
    +------------+  `master` +------------+
    |   `vxlan-X`|o--------->|  `br-X`    |
    +------------+           +------------+
                                    ^
                                    | `master`
                                    o
                             +------------+
                             |  `veth`    |
                             +------+-----+
                                    |
                          -         |        -
                         /          |         \
                        |    +------+-----+    |
                        |    |  `peer`    |    |
                        |    +------------+    +- container netns
                        |                      |
                        |                      |
                         \                    /
                          -                  -

Plugin
------

* `/opt/cni/bin/pyroute2-cni-plugin`
* a static binary that only forwards info the the server container

The plugin workflow:

1. executed by kubelet
2. get CNI json from `stdin`
3. get env variables
4. parse the variables and open `CNI_NETNS` → get open FD
5. obtain a new request id from the server
6. send the FD to the server
7. send the CNI and env data to the server
8. await the response
9. print out the response to `stdout`

Server
------

* a pod from the daemonset
* image:  `ghcr.io/svinota/pyroute2-cni:{version}`
* uses host network namespace
* mount host file system to expose communication sockets

The server workflow:

1. await request init
2. allocate and send a new request id
3. collect netns FD, CNI data and env variables from all the communication sockets
4. ensure the infrastructure on the node
5. create a veth pair, setup the container network
6. send CNI response to the plugin

.. aafig::
   :scale: 80
   :textual:

    kubelet                plugin                server
      o                     o                     o
      | `CNI_COMMAND: ADD`  |                     |
      +-------------------->|                     |
      |   json, env dict    |    request init     |
      |                     +-------------------->|    via `socket_path_api`
      |                     |                     |
      |                     |   get request id    |
      |                     |<--------------------+
      |                     |                     |
      |                     |   send netns data   |
      |                     +-------------------->|    via `socket_path_fd`
      |                     | \                   |
      |                     |  +-o request id     |
      |                     |  +-o open netns FD  |
      |                     |                     |
      |                     |                     |
      |                     |   send CNI data     |
      |                     +-------------------->|    via `socket_path_api`
      |                     | \                   |
      |                     |  +-o `request id`   |
      |                     |  +-o `CNI data`     |
      |                     |  +-o `env dict`     |
      |                     |                     |
      |                     |                     |  - - - - - -  `request ready`
      |                     |                     |
      |                     |                     |    `await setup_container_network()`
      |                     |                     |
      |                     |                     |     1. `ensure firewall`
      |                     |                     |     2. `ensure sysctl for VRF, SRv6, ...`
      |                     |                     |     3. `ensure the bridge`
      |                     |                     |     4. `ensure the VRF interface`
      |                     |                     |     5. `ensure the VXLAN interface`
      |                     |                     |     6. `create veth pair, setup the peer`
      |                     |                     |     7. `allocate and setup the address`
      |                     |   get CNI data      |
      |                     |<--------------------+
      |   `json to stdout`  |                     |
      |<--------------------+                     |
      |                     |                     |
      v                     v                     v
