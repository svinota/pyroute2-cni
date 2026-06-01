import logging
import os
import socket
from configparser import ConfigParser
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network
from typing import Any, Callable

from pyroute2 import AsyncIPRoute
from pyroute2.common import uifname

from kubernetes import client as k8s_client
from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.kubernetes import get_pod_tag
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest
from pyroute2_cni.vrf_domain import parse_vrf_domain


@dataclass
class SegmentInfo:
    prefix: str
    prefixlen: int
    vrf_table: int
    ipaddr: str
    gateway: str
    lladdr: str = ''


class Plugin(PluginProtocol):
    def __init__(
        self, config: ConfigParser, address_pool: AddressPool
    ) -> None:
        self.config = config
        self.address_pool = address_pool
        self.peer_ips: list[str] = []
        self.is_control_plane = False
        self.on_frr_ready: Callable[[], None] | None = None

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

    def refresh_frr_peers(self, v1: k8s_client.CoreV1Api) -> None:
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

    async def reconcile_routes(
        self,
        ipr: AsyncIPRoute,
        block_cidrs: set[IPv4Network],
        br_ifname: str,
        table: int,
    ) -> None:
        oif = await ipr.link_lookup(ifname=br_ifname)
        if not oif:
            logging.info(f'skip routes for missing bridge {br_ifname}')
            return
        for cidr in block_cidrs:
            await ipr.route(
                'replace',
                dst=str(cidr.network_address),
                dst_len=cidr.prefixlen,
                oif=oif,
                table=table,
            )

    async def ensure_segment(
        self,
        namespace: str,
        request: CNIRequest | None = None,
        mask: int = 0xFFFFFFFF,
    ) -> SegmentInfo:
        if request is None:
            raise RuntimeError("invalid path")
        config = self.config
        pod_uid: str | None = None
        net_ns_fd: int = 0

        pod_uid = get_pod_tag(request, 'uid')
        net_ns_fd = request.netns

        bindings = self.address_pool.k8s_custom_api.list_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomainbindings'
        )
        items = bindings.get('items', [])
        vrfd_name = None
        for item in items:
            spec = item.get('spec') or {}
            namespace_ref = spec.get('namespaceRef') or {}
            if namespace_ref.get('name') == namespace:
                vrfd_name = (spec.get('vrfDomainRef') or {}).get('name')
                break
        if vrfd_name is None:
            vrfd_name = f'vrf-{self.config["default"]["vrf"]}'

        raw_domain = (
            self.address_pool.k8s_custom_api.get_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', vrfd_name
            )
        )
        domain = parse_vrf_domain(raw_domain)

        prefix = domain.prefix or str(config['default']['prefix'])
        prefixlen = domain.prefixlen or int(config['default']['prefixlen'])
        network = IPv4Network(f'{prefix}/{prefixlen}')
        bridge_ifname = f'l2br-{domain.vrf}'
        uplink = uifname()

        async with AsyncIPRoute() as ipr_main:
            bridge_idx = (await ipr_main.link_lookup(ifname=bridge_ifname))[0]
            bridge_address = [
                x.get('address')
                async for x in await ipr_main.addr(
                    'dump', index=bridge_idx, family=socket.AF_INET
                )
            ]
            # create & attach veth pair
            veth = await ipr_main.ensure(
                ipr_main.link,
                present=True,
                ifname=uplink,
                kind='veth',
                peer={'ifname': 'eth0', 'net_ns_fd': net_ns_fd},
                state='up',
                master=bridge_idx,
            )
            gateway = [
                x.get('address')
                async for x in await ipr_main.addr(
                    'dump', index=bridge_idx, family=socket.AF_INET
                )
            ][0]
        veth_ipaddr = await self.address_pool.allocate(
            network,
            domain.ipblocklen,
            domain.vrf,
            is_gateway=False,
            pod_uid=pod_uid,
        )
        info = SegmentInfo(
            prefix=prefix,
            prefixlen=prefixlen,
            vrf_table=domain.table or domain.vrf,
            ipaddr=f'{veth_ipaddr}/{prefixlen}',
            gateway=gateway,
        )

        logging.info(f'segment {info}')

        async with AsyncIPRoute(netns=net_ns_fd) as ipr:
            veth = (await ipr.link('get', ifname='eth0'))[0]
            info.lladdr = veth.get('address')
            await ipr.link('set', index=veth.get('index'), state='up')
            await ipr.ensure(
                ipr.addr,
                present=True,
                index=veth.get('index'),
                address=info.ipaddr,
            )
            if bridge_address:
                await ipr.route('add', gateway=bridge_address[0])
            logging.info(f'info: {asdict(info)}')

        return info

    async def resync(self) -> None:
        local_node_name = self.config['network']['node_name']
        live_pod_ips: dict[str, str] = {}
        pods = self.address_pool.k8s_v1.list_pod_for_all_namespaces(
            field_selector=f'spec.nodeName={local_node_name}'
        )
        for pod in pods.items:
            metadata = pod.metadata
            status = pod.status
            if metadata is None or status is None:
                continue
            pod_uid = metadata.uid
            pod_ip = status.pod_ip
            if not pod_uid or not pod_ip:
                continue
            live_pod_ips[pod_uid] = pod_ip

        vrf_domains = (
            self.address_pool.k8s_custom_api.list_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
            )
        )
        for item in vrf_domains.get('items', []):
            domain = parse_vrf_domain(item)
            if domain.network is None:
                continue
            prefix = domain.prefix or str(self.config['default']['prefix'])
            prefixlen = domain.prefixlen or int(
                self.config['default']['prefixlen']
            )
            network = IPv4Network(f'{prefix}/{prefixlen}')
            gateway_ip = []
            async with AsyncIPRoute() as ipr:
                gateway_idx = await ipr.link_lookup(f'l2br-{domain.vrf}')
                if gateway_idx:
                    gateway_ip = [
                        x.get('address')
                        async for x in await ipr.addr(
                            'dump', index=gateway_idx[0], family=socket.AF_INET
                        )
                    ]
            await self.address_pool.prune_stale_allocations(
                network=network,
                vrf_table=domain.vrf,
                live_pod_ips=live_pod_ips,
                gateway_ip=gateway_ip[0] if gateway_ip else None,
            )

    async def cleanup(
        self, data: dict[str, Any], request: CNIRequest
    ) -> dict[str, Any]:
        '''
        Run network cleanup
        '''
        pod_uid = get_pod_tag(request, 'uid')
        try:
            await self.address_pool.release(pod_uid)
        except KeyError:
            # just ignore non existent addresses for now
            logging.error(f'pod_uid {pod_uid} not registered')
        try:
            await self.address_pool.gc_empty_blocks()
        except Exception as e:
            logging.warning(f'empty IPBlock gc failed: {e}')
        return data

    async def setup(
        self, data: dict[str, Any], request: CNIRequest
    ) -> dict[str, Any]:
        '''
        Run network setup
        '''
        await request.ready()
        logging.info(f'request {request.rid} ready')

        namespace = get_pod_tag(request, 'namespace', default='default')
        info = await self.ensure_segment(namespace, request)

        data['interfaces'] = [
            {
                'name': 'eth0',
                'mac': info.lladdr,
                'sandbox': request.env['CNI_NETNS'],
            }
        ]
        data['ips'] = [
            {'address': info.ipaddr, 'interface': 0, 'gateway': info.gateway}
        ]
        data['routes'] = [{'dst': '0.0.0.0/0'}]
        os.close(request.netns)
        logging.info(f'response: {data}')
        return data
