import asyncio
import time
from configparser import ConfigParser
from pathlib import Path
from string import Template
from typing import Any

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from pyroute2_cni.kubernetes import get_cluster_custom_object
from pyroute2_cni.vrf_domain import VRFDomain


class FRRManager:
    def __init__(self, template_path: str, config: ConfigParser) -> None:
        self.template_path = Path(template_path)
        self.config = config
        self.output_path = Path('/etc/frr/frr.conf')
        self.reload_sock = '/var/run/frr/reload.sock'
        self.peer_ips: list[str] = []
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

    def _node_router_id(self, node_name: str, node: Any | None = None) -> str:
        try:
            obj = get_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfnodeconfigs', node_name
            )
            spec = obj.get('spec') or {}
            router_id = spec.get('routerId')
            if router_id:
                return str(router_id)
        except ApiException as e:
            if e.status != 404:
                raise

        if node is not None:
            peer_ip = self._node_peer_ip(node)
            if peer_ip is not None:
                return peer_ip

        return self.config['network']['ipaddr']

    def _node_route_reflectors(self, node_name: str) -> list[str]:
        try:
            obj = get_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfnodeconfigs', node_name
            )
            spec = obj.get('spec') or {}
            rr_list = spec.get('routeReflectors') or []
            if rr_list:
                return [str(item) for item in rr_list if str(item)]
        except ApiException as e:
            if e.status != 404:
                raise
        return []

    def refresh_peers(self, v1: k8s_client.CoreV1Api) -> set[str]:
        peer_ips: set[str] = set()
        local_node_name = self.config['network']['node_name']
        self.router_id = self._node_router_id(local_node_name)
        for peer in self._node_route_reflectors(local_node_name):
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
            peer_ips.add(self._node_router_id(node.metadata.name, node))
        return peer_ips

    def render_config(
        self, vrfs: dict[int, VRFDomain], cleanup: dict[int, VRFDomain]
    ) -> str:
        vrf_sections = []
        vrf_router_sections = []
        for item in cleanup.values():
            vrf_sections.append(
                f'no vrf vrf-{item.vrf}\n'
                f'no router bgp 65000 vrf vrf-{item.vrf}\n'
            )
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
            f' neighbor {peer} peer-group PR2' for peer in self.peer_ips
        )

        template = Template(self.template_path.read_text(encoding='utf-8'))
        return template.substitute(
            router_id=self.router_id,
            peer_records=peer_records,
            vrf_sections='\n!\n'.join(vrf_sections),
            vrf_router_sections='\n!\n'.join(vrf_router_sections),
        )

    async def reload(
        self, vrfs: dict[int, VRFDomain], cleanup: dict[int, VRFDomain]
    ) -> None:
        self.peer_ips = list(
            sorted(self.refresh_peers(k8s_client.CoreV1Api()))
        )
        self.output_path.write_text(
            self.render_config(vrfs, cleanup), encoding='utf-8'
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
