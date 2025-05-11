Learn CNI Internals
===================

One of the most effective ways to learn a topic is by doing. This directory
provides a framework for experimenting with CNI in Python.

The main challenge with Python-based CNI plugins is that you cannot run the
plugin directly from the host system. Not every host has the required Python
version — or Python at all.

The solution is to run the logic in a container, forwarding all data from
the statically linked plugin to that container. See more details on this
communication here: https://pyroute2.org/cni/architecture.html#server

This `/learning` directory contains files to help you build your own image
based on `pyroute2-cni`, with custom logic to manage networking.

All the plumbing is already in place: the base image sets up the CNI config
and plugin on the host, starts the server, establishes communication between
the server and the plugin, and even includes the default IPAM module,
`pyroute2_cni.address_pool`.

Your module must provide three asynchronous methods:

* ``async def resync()``
  Reads the system state on startup and performs recovery if needed.

* ``async def cleanup()``
  Runs on pod/container deletion.

* ``async def setup()``
  Runs on pod/container creation.

All methods must be asynchronous; the server uses ``asyncio``. The event loop
will be provided. If your code uses components that start their own event
loop (e.g., ``asyncio.run()``), consider running them in a separate thread
or process to avoid conflicts.

Your plugin should provide an entry point named `pyroute2.cni network`
(see `setup.cfg`). The server uses this entry point to load the network
management code. If no custom module is specified, it will fall back to
the default module `pyroute2_cni.network`.

Steps to Build and Run Your Own Plugin
--------------------------------------

1. Use this directory as a skeleton, or edit `my_plugin/cni.py` in place.
2. Build the image: `podman build -t ${your_tag} .`
3. Push the image to your registry: `podman push ${your_tag}`
4. Replace `ghcr.io/svinota/pyroute2-cni:${version}` in the DaemonSet manifest
   `/kubernetes/pyroute2-cni.yaml` with `${your_tag}`.
5. Apply the updated manifest to your Kubernetes cluster:
   `kubectl apply -f ../kubernetes/pyroute2-cni.yaml`
6. Wait for the DaemonSet to start, check the logs, inspect the host systems,
   and begin experimenting.
