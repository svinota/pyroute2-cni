Decisions log
=============

This document tracks important technical and security decisions for
``pyroute2-cni``. Keep entries concise, evidence-based, and easy to revisit.
The decisions are documented in reverse chronological order (newest first).
Decision IDs use the format ``YYYYMMDD-XX``.

How to use
----------

* Record decisions that change architecture, security posture, operations,
  observability, or compatibility.
* Use one entry per decision.
* Update status as decisions evolve.
* Do not delete historical entries; mark superseded/rejected and reference the
  newer decision ID.

Status values
-------------

* ``proposed``: under discussion, not yet adopted
* ``accepted``: approved and current
* ``superseded``: replaced by a newer accepted decision
* ``rejected``: considered and explicitly not adopted

Implementation values
---------------------

* ``planned``: not started yet
* ``in-progress``: implementation work is underway
* ``partial``: implemented in part, follow-up required
* ``implemented``: fully applied in code/manifests

Index
-----

.. list-table::
   :header-rows: 1
   :widths: 22 48 14 16

   * - ID
     - Title
     - Status
     - Implementation
   * - :ref:`20261115-01 <decision-20261115-01>`
     - Enable BGP graceful restart
     - accepted
     - implemented
   * - :ref:`20261110-02 <decision-20261110-02>`
     - CM is the only writer of CNIStatus objects
     - accepted
     - planned
   * - :ref:`20261110-01 <decision-20261110-01>`
     - CNI role is read-only for non-IPAM CRDs
     - accepted
     - implemented


Decision template
-----------------

Copy this block for new entries.

.. code-block:: rst

   YYYYMMDD-XX: <Short title>
   ~~~~~~~~~~~~~~~~~~~~~~~~~~

   :Status: proposed|accepted|superseded|rejected
   :Implementation: planned|in-progress|partial|implemented
   :Supersedes: <optional decision ID>
   :Superseded-by: <optional decision ID>

   Context
   ^^^^^^^

   <Why this decision is needed.>

   Decision
   ^^^^^^^^

   <What we decided.>

   Alternatives considered
   ^^^^^^^^^^^^^^^^^^^^^^^

   * <Alternative A and why not chosen>
   * <Alternative B and why not chosen>

   Consequences
   ^^^^^^^^^^^^

   * <Consequence A>
   * <Consequence B>

   Evidence and references
   ^^^^^^^^^^^^^^^^^^^^^^^

   * Code: ``path/to/file.py``
   * Config: ``path/to/manifest.yaml``
   * Tracking: ``issue/PR/reference``

   Review trigger
   ^^^^^^^^^^^^^^

   <When this should be revisited.>


Entries
-------

.. _decision-20261115-01:

20261115-01: Enable BGP graceful-restart
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Status: accepted
:Implementation: implemented

Context
^^^^^^^

Talos uplink interface restarts can interrupt BGP sessions even when the
node's workload networking configuration remains intact. Immediately
withdrawing learned routes during these transient interruptions adds
control-plane churn and can delay recovery after the uplink returns.

Decision
^^^^^^^^

Enable BGP graceful-restart in the shared FRR configuration template for
the main BGP instance carrying the cluster's IPv4 and EVPN sessions:

.. code-block:: text

   bgp graceful-restart
   bgp graceful-restart restart-time 30
   bgp graceful-restart stalepath-time 120

Use a 30-second restart time and a 120-second stale-path time to allow
short interruptions while bounding stale-route retention. Route retention
depends on negotiated graceful-restart capabilities and peer behavior;
these settings are not a guarantee of uninterrupted forwarding.

Alternatives considered
^^^^^^^^^^^^^^^^^^^^^^^

* Immediate route withdrawal on session loss: removes failed paths promptly,
  but causes avoidable route churn during transient uplink restarts.
* Longer BGP hold timers alone: delay failure detection rather than provide
  graceful-restart route retention and recovery.

Consequences
^^^^^^^^^^^^

* Compatible peers can retain routes during eligible session interruptions,
  reducing withdrawals and subsequent route relearning.
* Traffic can still be lost while the uplink or forwarding path is down.
* Retained stale routes can blackhole traffic after a genuine node or
  forwarding failure until they are removed or replaced.
* Peer capability negotiation and recovery behavior must be verified in
  deployments, including any external route reflectors.
* This does not establish pod network readiness or replace end-to-end
  connectivity checks.

Evidence and references
^^^^^^^^^^^^^^^^^^^^^^^

* Config: ``kubernetes/base/0.3/config.yaml``, ``frr.conf.tpl``.
* Commit: ``74bd3845297cbeb19786616b6e656d23062fe62d``
  (``frr: use graceful-restart``), introduced for Talos uplink restarts.

Review trigger
^^^^^^^^^^^^^^

Revisit the timers or enablement if transient restarts exceed the recovery
window, stale routes prolong outages, or the FRR version or peer topology
changes. Validate both transient uplink recovery and permanent node failure.


.. _decision-20261110-02:

20261110-02: CM is the only writer of CNIStatus objects
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Status: accepted
:Implementation: planned

Context
^^^^^^^

``CNIStatus`` CRD is planned as a cluster-wide status surface for subsystems
(``config``, ``bgp``, ``evpn``, ``ipam``, etc.). Allowing node-local,
privileged CNI/FRR containers to write these objects would expand write
capabilities, weaken least-privilege boundaries, and possibly lead to write
races.

Decision
^^^^^^^^

Only the CM pod writes ``CNIStatus`` objects and their status subresources.
Node-local CNI/FRR containers publish health via probe/metrics endpoints and
remain non-writers for ``CNIStatus``.

The CM pod observes the local node for BGP/FDB inconsistencies to catch
failures quickly, but relies on metrics to mark subsystems as healthy.

Alternatives considered
^^^^^^^^^^^^^^^^^^^^^^^

* Per-node push directly to ``CNIStatus`` CRDs (rejected: broad write surface).
* Per-node push to CM HTTP endpoint (rejected: requires an additional
  authentication/authorization layer).

Consequences
^^^^^^^^^^^^

* Single trusted writer, simpler audit trail, stronger RBAC boundaries.
* Consistent cluster-wide aggregation semantics.
* CM must discover and poll node endpoints, and handle partial
  visibility/staleness.

Review trigger
^^^^^^^^^^^^^^

Revisit if CM polling becomes too latent/expensive.


.. _decision-20261110-01:

20261110-01: CNI role is read-only for non-IPAM CRDs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

:Status: accepted
:Implementation: implemented

Context
^^^^^^^

The CNI DaemonSet runs privileged on every node and has broad cluster impact.
To reduce blast radius, the CNI role should follow strict least privilege.

Decision
^^^^^^^^

The ``pyroute2-cni-clusterrole`` role must be restricted as follows:

* For non-IPAM CRDs, allow read-only access (``get``, ``list``, ``watch``).
* Allow updates only for status subresources where needed for reconciliation.
* Keep write access for IPAM CRDs required by node-local allocation flows.
* Do not grant spec mutation rights for other CNI CRDs.

Alternatives considered
^^^^^^^^^^^^^^^^^^^^^^^

* Keep broad write permissions in the CNI role (rejected: larger compromise
  impact).
* Move all writes to CNI and remove CM writes (rejected: weakens separation
  of duties).

Consequences
^^^^^^^^^^^^

* Reduced control-plane abuse surface from privileged node agents.

Review trigger
^^^^^^^^^^^^^^

Revisit if non-IPAM CRD write verbs are requested for CNI SA.
