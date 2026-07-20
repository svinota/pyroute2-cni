from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class VRFRoutingPolicyVRFDomainRef:
    name: str


@dataclass(frozen=True)
class VRFRoutingPolicyMatch:
    dst: str | None = None
    src: str | None = None
    oifname: str | None = None
    iifname: str | None = None


@dataclass(frozen=True)
class VRFRoutingPolicy:
    name: str
    generation: int
    vrf_domain_ref: VRFRoutingPolicyVRFDomainRef
    match: list[VRFRoutingPolicyMatch]
    deletion_timestamp: str = ''

    def render(self) -> dict[str, Any]:
        metadata: dict[str, Any] = {'name': self.name}
        if self.deletion_timestamp:
            metadata['deletionTimestamp'] = self.deletion_timestamp
        return {
            'apiVersion': 'cni.pyroute2.org/v1alpha1',
            'kind': 'VRFRoutingPolicy',
            'metadata': metadata,
            'spec': {
                'vrfDomainRef': {'name': self.vrf_domain_ref.name},
                'match': [
                    {
                        key: value
                        for key, value in {
                            'dst': item.dst,
                            'src': item.src,
                            'oifname': item.oifname,
                            'iifname': item.iifname,
                        }.items()
                        if value is not None
                    }
                    for item in self.match
                ],
            },
        }


def parse_vrf_routing_policy(item: dict[str, Any]) -> VRFRoutingPolicy:
    metadata = item.get('metadata') or {}
    spec = item.get('spec') or {}
    vrf_domain_ref = spec.get('vrfDomainRef') or {}
    match = [
        VRFRoutingPolicyMatch(
            dst=entry.get('dst'),
            src=entry.get('src'),
            oifname=entry.get('oifname'),
            iifname=entry.get('iifname'),
        )
        for entry in spec.get('match') or []
    ]
    return VRFRoutingPolicy(
        name=str(metadata.get('name') or ''),
        generation=int(metadata.get('generation') or 0),
        vrf_domain_ref=VRFRoutingPolicyVRFDomainRef(
            name=str(vrf_domain_ref.get('name') or '')
        ),
        match=match,
        deletion_timestamp=str(metadata.get('deletionTimestamp') or ''),
    )
