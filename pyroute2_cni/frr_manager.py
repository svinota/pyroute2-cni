import asyncio
import time
from configparser import ConfigParser
from pathlib import Path
from string import Template
from typing import Any

from kubernetes import client as k8s_client
from pyroute2_cni.kubernetes import get_node_annotations
from pyroute2_cni.vrf_domain import VRFDomain


class FRRManager:
    def __init__(self, template_path: str, config: ConfigParser) -> None:
        self.template_path = Path(template_path)
        self.config = config
        self.output_path = Path('/etc/frr/frr.conf')
        self.reload_sock = '/var/run/frr/reload.sock'
        self.peer_ips: list[str] = []

    @staticmethod
    def _node_peer_ip(node: Any) -> str | None:
        addresses = getattr(node.status, 'addresses', None) or []
        for addr in addresses:
            if addr.type == 'InternalIP':
                return addr.address
        for addr in addresses:
            if addr.type == 'ExternalIP':
                return addr.address
        return None

    def refresh_peers(self, v1: k8s_client.CoreV1Api) -> None:
        peer_ips = []
        local_node_name = self.config['network']['node_name']
        for node in v1.list_node().items:
            if node.metadata and node.metadata.name == local_node_name:
                continue
            peer_ip = self._node_peer_ip(node)
            if peer_ip is None:
                continue
            peer_ips.append(peer_ip)
        self.peer_ips = sorted(set(peer_ips))

    def render(self, vrfs: dict[int, VRFDomain]) -> str:
        vrf_sections = []
        vrf_router_sections = []
        for item in vrfs.values():
            section = (
                f'router bgp 65000 vrf vrf-{item.vrf}\n'
                f' !\n'
                f' address-family ipv4 unicast\n'
                f'  redistribute connected\n'
                f'  redistribute static\n'
                f'  redistribute kernel\n'
                f' exit-address-family\n'
                f' !\n'
                f' address-family l2vpn evpn\n'
                f'  advertise ipv4 unicast\n'
            )
            for attachment in item.attachments:
                if attachment.kind == 'l3vni':
                    vrf_sections.append(
                        f'vrf vrf-{item.vrf}\n vni {attachment.vni}\nexit-vrf'
                    )
                # section += (
                #     f'  route-target import 65000:{item.vrf}\n'
                #     f'  route-target export 65000:{item.vrf}\n'
                # )
            section += ' exit-address-family\n' 'exit'
            vrf_router_sections.append(section)

        bgp_config = (
            self.config['bgp'] if self.config.has_section('bgp') else {}
        )
        rr_mode = bgp_config.get('rr_mode', 'mesh')
        peer_records = ''
        router_id = self.config['network']['ipaddr']

        if rr_mode == 'mesh':
            peer_records += '\n'.join(
                f' neighbor {peer} peer-group PR2' for peer in self.peer_ips
            )
        elif rr_mode == 'node-annotation':
            node_name = self.config['network']['node_name']
            node_rr_annotation = (
                get_node_annotations(node_name).get('pyroute2.org/rr') or ''
            )
            rr_list = node_rr_annotation.split(';')
            if rr_list:
                peer_records += '\n'.join(
                    f' neighbor {peer} peer-group PR2' for peer in rr_list
                )

        template = Template(self.template_path.read_text(encoding='utf-8'))
        return template.substitute(
            router_id=router_id,
            peer_records=peer_records,
            vrf_sections='\n!\n'.join(vrf_sections),
            vrf_router_sections='\n!\n'.join(vrf_router_sections),
        )

    async def reload(
        self, vrfs: dict[int, VRFDomain], refresh: bool = True
    ) -> None:
        if refresh:
            self.refresh_peers(k8s_client.CoreV1Api())
        self.output_path.write_text(self.render(vrfs), encoding='utf-8')
        deadline = time.monotonic() + 120
        read_timeout = 30
        while True:
            try:
                reader, writer = await asyncio.open_unix_connection(
                    self.reload_sock
                )
            except FileNotFoundError:
                if time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(0.5)
                continue
            try:
                writer.write(b'reload\n')
                await writer.drain()
                await asyncio.wait_for(reader.read(64), timeout=read_timeout)
                return
            finally:
                writer.close()
                await writer.wait_closed()
