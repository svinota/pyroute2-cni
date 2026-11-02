Changelog
=========

0.2.0 (2026-11-02)
------------------

Improve installation routines and add config management
using CNIConfig and CNIConfigSelection.

Added
~~~~~

- CRD: CNIConfig: define CNI config file
- CRD: CNIConfigSelection: select the desired CNI configuration
- CRD: VRFRoutingPolicy: define custom routing policies

Changed
~~~~~~~

- FRR: restart container on FDB discrepancies
- Tolerate network restart during CNI pod startup
- Fix IPBlock management: don't remove the only IPBlock in VRF
- Fix install: handle errors on config deployment

0.1.0 (2026-06-18)
------------------

Initial public release

Added
~~~~~

- FRR runtime: bgpd, zebra, staticd
- FRR config: `vrf`, `router bgp` sections
- Dataplane: EVPN-VXLAN Type-5
- EVPN Type-5 prefix propagation to/from PE
- CRD: IPBlock: IPAM database, represent routed subranges
- CRD: VRFDomain attachments: l2vni, l3vni
- CRD: VRFNodeConfig: custom local VTEP address, optional RR list
- CRD: VRFDomainBinding: namespace-to-VRF mapping
