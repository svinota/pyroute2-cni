from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Any

from pyroute2 import AsyncIPRoute


@dataclass(frozen=True)
class VRFAttachment:
    kind: str
    vni: int
    dev: str
    port: int

    async def fetch_local(self) -> str:
        async with AsyncIPRoute() as ipr:
            index = (await ipr.link_lookup(ifname=self.dev))[0]
            return [x async for x in await ipr.addr('dump', index=index)][
                0
            ].get('address')


@dataclass(frozen=True)
class VRFDomain:
    name: str
    vrf: int
    table: int | None
    prefix: str | None
    prefixlen: int | None
    ipblocklen: int | None
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
                    {
                        'type': item.kind,
                        'vni': item.vni,
                        'dev': item.dev,
                        'port': item.port,
                    }
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
            dev=str(seg.get('dev', '')),
            port=int(seg.get('port', 4789)),
        )
        for seg in spec.get('attachments') or []
    ]
    return VRFDomain(
        name=str(metadata.get('name') or ''),
        vrf=int(spec['vrf']),
        table=int(spec['table']) if spec.get('table') is not None else None,
        prefix=spec.get('prefix'),
        prefixlen=(
            int(spec['prefixlen'])
            if spec.get('prefixlen') is not None
            else None
        ),
        ipblocklen=(
            int(spec['ipblocklen'])
            if spec.get('ipblocklen') is not None
            else None
        ),
        attachments=attachments,
    )
