import asyncio
import time
from configparser import ConfigParser
from pathlib import Path
from string import Template
from typing import Any

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from pyroute2_cni.crds.vrf_domain import VRFDomain, parse_vrf_domain
from pyroute2_cni.crds.vrf_node_config import (
    VRFNodeConfig,
    parse_vrf_node_config,
)


class FRRManager:
    def __init__(self, template_path: str, config: ConfigParser) -> None:
        self.template_path = Path(template_path)
        self.config = config
        self.output_path = Path('/etc/frr/frr.conf')
        self.vrf_custom_api = k8s_client.CustomObjectsApi()
        self.reload_sock = '/var/run/frr/reload.sock'
        self.peer_cache: set[str] = set()
        self.router_id: str = config['network']['ipaddr']

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

    def _get_node_config(self, node_name: str) -> VRFNodeConfig | None:
        try:
            response = self.vrf_custom_api.list_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfnodeconfigs'
            )
        except ApiException as e:
            if e.status != 404:
                raise
            return None

        for item in response.get('items', []):
            node_config = parse_vrf_node_config(item)
            if node_config.node_ref.name == node_name:
                return node_config
        return None

    def refresh_peers(self, v1: k8s_client.CoreV1Api) -> set[str]:
        peer_ips: set[str] = set()
        local_node_name = self.config['network']['node_name']
        node_config = self._get_node_config(local_node_name)
        if node_config is not None:
            if node_config.router_id:
                self.router_id = node_config.router_id
            for peer in node_config.route_reflectors:
                peer_ips.add(peer)
        if peer_ips:
            # RR are fetched, stop and return
            return peer_ips
        # no RRs found, build mesh network
        for node in v1.list_node().items:
            if node.metadata is None or node.metadata.name is None:
                continue
            if node.metadata.name == local_node_name:
                continue
            node_config = self._get_node_config(node.metadata.name)
            if node_config is not None and node_config.router_id:
                peer_ips.add(node_config.router_id)
                continue
            peer_ip = self._node_peer_ip(node)
            if peer_ip is not None:
                peer_ips.add(peer_ip)
        return peer_ips

    def vrf_domain_items(self) -> dict[int, VRFDomain]:
        response = self.vrf_custom_api.list_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
        )
        return dict(
            (
                (x.vrf, x)
                for x in (
                    parse_vrf_domain(item)
                    for item in response.get('items', [])
                )
            )
        )

    def render_config(
        self, vrf_cleanup: dict[int, VRFDomain], peer_cleanup: set[str]
    ) -> str:
        vrf_sections = []
        vrf_router_sections = []
        for item in vrf_cleanup.values():
            vrf_sections.append(
                f'no vrf vrf-{item.vrf}\n'
                f'no router bgp 65000 vrf vrf-{item.vrf}\n'
            )
        vrfs = {
            k: v
            for k, v in self.vrf_domain_items().items()
            if k not in vrf_cleanup
        }
        self.peer_cache = self.refresh_peers(k8s_client.CoreV1Api())
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
                section += (
                    f'  route-target import 65000:{item.vrf}\n'
                    f'  route-target export 65000:{item.vrf}\n'
                )
            section += ' exit-address-family\n' 'exit'
            vrf_router_sections.append(section)

        peer_records = '\n'.join(
            f' neighbor {peer} peer-group PR2' for peer in self.peer_cache
        )
        peer_cleanup_records = '\n'.join(
            f' no neighbor {peer} peer-group PR2'
            for peer in sorted(peer_cleanup)
        )

        template = Template(self.template_path.read_text(encoding='utf-8'))
        return template.substitute(
            router_id=self.router_id,
            peer_records='\n'.join(
                item for item in (peer_cleanup_records, peer_records) if item
            ),
            vrf_sections='\n!\n'.join(vrf_sections),
            vrf_router_sections='\n!\n'.join(vrf_router_sections),
        )

    async def reload(
        self, vrf_cleanup: dict[int, VRFDomain], peer_cleanup: set[str]
    ) -> None:
        if peer_cleanup is None:
            peer_cleanup = set()
        self.output_path.write_text(
            self.render_config(vrf_cleanup, peer_cleanup), encoding='utf-8'
        )
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
