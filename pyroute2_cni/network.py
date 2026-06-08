import logging
import os
from configparser import ConfigParser
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network
from typing import Any, Callable

from kubernetes.client.exceptions import ApiException
from pyroute2 import AsyncIPRoute
from pyroute2.common import uifname

from kubernetes import client as k8s_client
from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.kubernetes import get_pod_tag
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest
from pyroute2_cni.vrf_domain import parse_vrf_domain


class CNIError(RuntimeError):
    def __init__(
        self, code: int, msg: str, details: str | None = None
    ) -> None:
        super().__init__(details or msg)
        self.code = code
        self.msg = msg
        self.details = details or msg


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

        try:
            raw_domain = (
                self.address_pool.k8s_custom_api.get_cluster_custom_object(
                    'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', vrfd_name
                )
            )
        except ApiException as e:
            if e.status == 404:
                raise CNIError(
                    7,
                    'Invalid network config',
                    f'VRFDomain {vrfd_name} referenced by '
                    f'namespace {namespace} not found',
                ) from e
            raise
        domain = parse_vrf_domain(raw_domain)

        prefix = domain.prefix or str(config['default']['prefix'])
        prefixlen = domain.prefixlen or int(config['default']['prefixlen'])
        network = IPv4Network(f'{prefix}/{prefixlen}')
        bridge_ifname = domain.bridge_name()
        uplink = uifname()

        allocation = await self.address_pool.allocate(
            network, domain.ipblocklen, domain.vrf, pod_uid=pod_uid
        )
        veth_ipaddr = allocation.address.compressed
        bridge_ipaddr = allocation.gateway.compressed

        info = SegmentInfo(
            prefix=prefix,
            prefixlen=prefixlen,
            vrf_table=domain.table or domain.vrf,
            ipaddr=f'{veth_ipaddr}/{domain.bridge_prefixlen()}',
            gateway=bridge_ipaddr,
        )

        logging.info(f'segment {info}')

        async with AsyncIPRoute() as ipr_main:
            bridge_idx = (await ipr_main.link_lookup(ifname=bridge_ifname))[0]

            # create & attach veth pair
            veth = await ipr_main.ensure(
                ipr_main.link,
                present=True,
                ifname=uplink,
                kind='veth',
                mtu=1440,
                peer={'ifname': 'eth0', 'net_ns_fd': net_ns_fd, 'mtu': 1440},
                state='up',
                master=bridge_idx,
            )

            # set hairpin mode
            #
            # this setting is crucial to work via k8s svc redirect,
            # if the pod is providing and using the service at the
            # same time
            await ipr_main.brport('set', index=veth[0].get('index'), mode=1)

            # ensure gateway address
            await ipr_main.ensure(
                ipr_main.addr,
                present=True,
                index=bridge_idx,
                address=bridge_ipaddr,
                prefixlen=domain.bridge_prefixlen(),
            )

        async with AsyncIPRoute(netns=net_ns_fd) as ipr:
            veth = (await ipr.link('get', ifname='eth0'))[0]
            info.lladdr = veth.get('address')
            await ipr.link('set', index=veth.get('index'), state='up')
            await ipr.ensure(
                ipr.addr,
                present=True,
                index=veth.get('index'),
                address=veth_ipaddr,
                prefixlen=domain.bridge_prefixlen(),
            )
            await ipr.route('add', gateway=bridge_ipaddr)
            logging.info(f'info: {asdict(info)}')

        return info

    async def resync(self) -> None:
        pass

    async def cleanup(
        self, data: dict[str, Any], request: CNIRequest
    ) -> dict[str, Any]:
        '''
        Run network cleanup
        '''
        pod_uid = get_pod_tag(request, 'uid')
        net_ns_fd = request.netns
        # try to release the interface using netns
        if net_ns_fd > 0:
            async with AsyncIPRoute(netns=net_ns_fd) as ipr:
                await ipr.ensure(ipr.link, present=False, ifname='eth0')
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
