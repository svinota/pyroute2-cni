.. config:

CNI config management
=====================

This page describes how to manage host CNI config files with
`CNIConfig` and `CNIConfigSelection`.

Overview
--------

`pyroute2-cni` supports two CRDs for CNI config lifecycle:

* `CNIConfig` defines candidate CNI config payloads
* `CNIConfigSelection` points to the config that should be active

The flow is:

#. create one or more `CNIConfig` objects
#. set `CNIConfigSelection/default.spec.activeRef.name`
#. `pyroute2-cni` daemonset writes only the selected config file on each node

The active file is written under:

* `/host/etc/cni/net.d` inside the `pyroute2-cni` pod
* `/etc/cni/net.d` on the node filesystem

Prerequisites
-------------

Use CRDs version `0.2` or newer:

.. code-block::

    kubectl apply -k https://github.com/svinota/pyroute2-cni/kubernetes/crds/0.2/

Ensure both controllers are running:

* `pyroute2-cm` (cluster config manager)
* `pyroute2-cni` daemonset (node-local file writer)

Default CRDs
------------

By default, `pyroute2-cm` creates `CNIConfig` `cbr0` and
`CNIConfigSelection` `default`, which points to that `CNIConfig`.

The config has `spec.fileName: 99-pyroute2.conflist`, so it's safe to
deploy `pyroute2-cni` alongside other CNIs in order to experiment with it.

For production deployments, it is recommended to avoid dual CNI
installations.

Create a CNIConfig
------------------

Example:

.. code-block:: yaml

    apiVersion: cni.pyroute2.org/v1alpha1
    kind: CNIConfig
    metadata:
      name: pyroute2-test
    spec:
      fileName: 10-pyroute2-test.conflist
      plugins:
      - type: pyroute2-cni-plugin
      - capabilities: {}
        type: portmap
        
Fields:

* `spec.fileName`: target file name in `cni_config_dir`
* `spec.plugins`: plugin list written into the rendered CNI config

Selection behavior
------------------

`CNIConfigSelection/default.spec.activeRef.name` is the only supported source
of truth.

Example:

.. code-block:: yaml

    apiVersion: cni.pyroute2.org/v1alpha1
    kind: CNIConfigSelection
    metadata:
      name: default
    spec:
      activeRef:
        name: pyroute2-test

Node-local `pyroute2-cni` processes watch `CNIConfigSelection` and:

* write the active config file
* remove files for other non-selected `CNIConfig` objects
* ignore files that belong to other CNIs and have no corresponding `CNIConfig` object
* ignore `CNIConfigSelection` objects other than `default`

Rendered file format
--------------------

The node-side file is rendered as JSON with:

* `name`: from `CNIConfig.metadata.name`
* `cniVersion`: `0.4.0`
* `plugins`: from `CNIConfig.spec.plugins`

This allows you to manage complete plugin chains from Kubernetes CRDs.

Switch active config
--------------------

In order to switch the active config, update
`CNIConfigSelection/default.spec.activeRef.name`.

.. code-block::

    kubectl patch cnics default --type=merge -p \
      '{"spec":{"activeRef":{"name":"pyroute2-canary"}}}'

Operational checks
------------------

Inspect objects:

.. code-block::

    kubectl get cniconfig
    kubectl get cniconfigselection
    kubectl get cniconfigselection default -o yaml

Check active file on a node:

.. code-block::

    kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-cni -- ls -l /host/etc/cni/net.d

Check rendered content:

.. code-block::

    kubectl -n pyroute2-cni exec -ti daemonsets/pyroute2-cni -c pyroute2-cni -- cat /host/etc/cni/net.d/10-pyroute2-test.conflist

Notes
-----

* CRDs are cluster-scoped.
* Activation uses only `CNIConfigSelection.spec.activeRef.name`.
* If no `CNIConfig` exists, the config manager creates a default one automatically.
* Only `pyroute2-cm` bootstraps `CNIConfig` and `CNIConfigSelection/default`.
* If selection points to a missing `CNIConfig`, nodes keep the last good config.
* If `CNIConfigSelection/default` is deleted, CNI keeps the last good config until CM recreates it.
