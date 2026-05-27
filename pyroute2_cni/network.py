import errno
import logging
import os
import socket
from configparser import ConfigParser
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network
from typing import Any, Callable

from pyroute2 import AsyncIPRoute, NetlinkError
from pyroute2.common import uifname

from kubernetes import client as k8s_client
from pyroute2_cni.address_pool import AddressPool, IPBlockConflict
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

        bindings = (
            self.address_pool.k8s_custom_api.list_namespaced_custom_object(
                'cni.pyroute2.org', 'v1alpha1', namespace, 'vrfdomainbindings'
            )
        )
        items = bindings.get('items', [])
        if items:
            vrfd_name = (
                (items[0].get('spec') or {})
                .get('vrfDomainRef', {})
                .get('name')
            )
        else:
            vrfd_name = 'vrf-42'

        raw_domain = (
            self.address_pool.k8s_custom_api.get_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', vrfd_name
            )
        )
        domain = parse_vrf_domain(raw_domain)

        attachment = next(
            item for item in domain.attachments if item.kind == 'l2vni'
        )
        prefix = domain.prefix or str(config['default']['prefix'])
        prefixlen = domain.prefixlen or int(config['default']['prefixlen'])
        network = IPv4Network(f'{prefix}/{prefixlen}')
        bridge_ifname = f'l2ibr-{attachment.vni}'
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
            domain.vrf,
            attachment.vni,
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
        return
        config = self.config

        v1 = k8s_client.CoreV1Api()
        self.refresh_frr_peers(v1)
        node_name = self.address_pool.node_name
        live_pod_ips = {
            pod.metadata.uid: pod.status.pod_ip
            for pod in v1.list_pod_for_all_namespaces(
                field_selector=f'spec.nodeName={node_name}'
            ).items
            if pod.metadata
            and pod.metadata.uid
            and pod.status
            and pod.status.pod_ip
        }
        networks = set()
        default_prefix = config['default']['prefix']
        default_prefixlen = config['default']['prefixlen']
        default_vrf = int(config['default']['vrf'])
        default_l2vni = int(config['default']['l2vni'])
        default_l3vni = int(config['default']['l3vni'])
        networks.add(
            (
                IPv4Network(f'{default_prefix}/{default_prefixlen}'),
                default_vrf,
                default_l2vni,
                default_l3vni,
            )
        )

        for network, vrf_table, l2vni, _l3vni in networks:
            br_ifname = f'br-{vrf_table}'
            gateway_ip = None
            async with AsyncIPRoute() as ipr:
                block_cidrs = self.address_pool.block_cidrs(
                    network, vrf_table, l2vni
                )
                br_idx = await ipr.link_lookup(ifname=br_ifname)
                if not br_idx:
                    continue
                bridge_addr = [
                    x
                    async for x in await ipr.addr(
                        'dump', family=socket.AF_INET, index=br_idx[0]
                    )
                ]
                if bridge_addr:
                    gateway_ip = bridge_addr[0].get('address')
                    try:
                        await self.address_pool.restore(
                            network=network,
                            vrf_table=vrf_table,
                            l2vni=l2vni,
                            is_gateway=True,
                            address=self.address_pool.inet_aton(
                                network, gateway_ip
                            ),
                        )
                    except IPBlockConflict as err:
                        logging.warning(
                            'skipping bridge gateway restore for %s: %s',
                            gateway_ip,
                            err,
                        )
                    await self.address_pool.restore_live_allocations(
                        network, vrf_table, l2vni, live_pod_ips
                    )
                    await self.address_pool.prune_stale_allocations(
                        network, vrf_table, l2vni, live_pod_ips, gateway_ip
                    )

                table = 254
                service_vrf_max = (
                    int(config['default']['service_vrf_max']) or 1024
                )
                if vrf_table > service_vrf_max:
                    table = vrf_table

                # Cleanup broad prefix routes possibly left from
                # previous versions
                try:
                    await ipr.route(
                        'del',
                        dst=str(network.network_address),
                        dst_len=network.prefixlen,
                        table=table,
                    )
                except NetlinkError as e:
                    if e.code != errno.ESRCH:
                        raise
                await self.reconcile_routes(ipr, block_cidrs, br_ifname, table)

        await self.address_pool.gc_empty_blocks()

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
