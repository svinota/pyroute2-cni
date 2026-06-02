from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Any


@dataclass(frozen=True)
class VRFAttachment:
    kind: str
    vni: int
    port: int


@dataclass(frozen=True)
class VRFDomain:
    name: str
    vrf: int
    table: int
    prefix: str
    prefixlen: int
    ipblocklen: int
    attachments: list[VRFAttachment]

    @property
    def vrf_name(self) -> str:
        return f'vrf-{self.vrf}'

    @property
    def network(self) -> IPv4Network | None:
        if self.prefix is None or self.prefixlen is None:
            return None
        return IPv4Network(f'{self.prefix}/{self.prefixlen}')

    @property
    def l2vni(self) -> int:
        for segment in self.attachments:
            if segment.kind == 'l2vni':
                return segment.vni
        return self.vrf

    @property
    def l3vni(self) -> int:
        for segment in self.attachments:
            if segment.kind == 'l3vni':
                return segment.vni
        return 0

    def render(self) -> dict[str, Any]:
        return {
            'apiVersion': 'cni.pyroute2.org/v1alpha1',
            'kind': 'VRFDomain',
            'metadata': {'name': self.name},
            'spec': {
                'vrf': self.vrf,
                'table': self.table,
                'prefix': self.prefix,
                'prefixlen': self.prefixlen,
                'ipblocklen': self.ipblocklen,
                'attachments': [
                    {'type': item.kind, 'vni': item.vni, 'port': item.port}
                    for item in self.attachments
                ],
            },
        }


def parse_vrf_domain(item: dict[str, Any]) -> VRFDomain:
    metadata = item.get('metadata') or {}
    spec = item.get('spec') or {}
    attachments = [
        VRFAttachment(
            kind=str(seg.get('type', '')),
            vni=int(seg.get('vni', 0)),
            port=int(seg.get('port', 4789)),
        )
        for seg in spec.get('attachments') or []
    ]
    return VRFDomain(
        name=str(metadata.get('name') or ''),
        vrf=int(spec['vrf']),
        table=int(spec['table']),
        prefix=str(spec['prefix']),
        prefixlen=int(spec['prefixlen']),
        ipblocklen=int(spec['ipblocklen']),
        attachments=attachments,
    )
