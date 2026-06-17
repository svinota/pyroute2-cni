.. pyroute2-cni documentation master file

.. container:: rightside

    .. image:: _images/CNI-hld.svg
       :target: _images/CNI-hld.svg

pyroute2-cni
============

pyroute2-cni is a Kubernetes networking layer for service provider and
enterprise environments built around VRFs and BGP-routed network fabrics.

Instead of introducing a Kubernetes-specific networking model, pyroute2-cni
integrates workloads directly into existing routing domains, allowing
Kubernetes clusters to participate as first-class citizens in established
network architectures.

Core capabilities
-----------------

* **VRF-native workload networking**: Workloads are attached directly to
  VRFs, making routing domains the primary mechanism for segmentation and
  connectivity.
* **BGP-driven integration**: Clusters integrate with existing routing
  infrastructures through BGP, supporting both internal mesh deployments
  and external route reflectors.
* **EVPN-VXLAN interoperability**: EVPN-VXLAN integration enables
  interoperability with modern L2/L3 service fabrics and data center networks.
* **Multi-tenant operation**: The design supports large-scale multi-tenancy,
  including overlapping IP address spaces across independent tenants.

Architectural principles
------------------------

- Network-fabric-first design
- VRFs as the unit of segmentation and tenancy
- BGP as the control plane for external connectivity
- Minimal dependency on Kubernetes-specific networking abstractions
- Alignment with existing operational and troubleshooting models

Target environments
-------------------

- Service provider Kubernetes platforms
- Network Functions Virtualization (NFV) and cloud-native network functions
  (CNFs)
- Multi-tenant container platforms with overlapping address spaces
- Enterprise and provider networks built around VRFs, BGP, and EVPN fabrics
- Hybrid infrastructures combining containers, virtual machines, and
  traditional network services

Non-goals
---------

pyroute2-cni is not intended to be:

- A Kubernetes NetworkPolicy implementation
- An L7 security or service mesh platform
- An application observability framework

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   quickstart
   general
   architecture
