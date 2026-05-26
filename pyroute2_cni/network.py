import errno
import logging
import os
import socket
from configparser import ConfigParser
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network
from string import Template
from typing import Any, Callable

from pyroute2 import AsyncIPRoute, NetlinkError

from kubernetes import client as k8s_client
from pyroute2_cni.address_pool import AddressPool, IPBlockConflict
from pyroute2_cni.firewall import FirewallManager
from pyroute2_cni.kubernetes import get_namespace_annotations, get_pod_tag
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest


def set_sysctl(config: dict[str, int]) -> None:
    for path, value in config.items():
        with open(f'/proc/sys/{path.replace(".", "/")}', 'w') as f:
            f.write(str(value))


@dataclass
class SegmentInfo:
    prefix: str
    prefixlen: int
    vrf_table: int
    l2vni: int
    l3vni: int
    host_link: int
    host_ifname: str
    host_order: int
    namespace: str
    net_ns_fd: int = 0
    host_ipaddr: str = ''
    veth_ipaddr: str = ''
    br_ipaddr: str = ''
    vrf_ifname: str = ''
    br_ifname: str = ''
    vxlan_ifname: str = ''
    vxlan_local: str = ''
    veth_mac: str = ''
    pod_name: str = ''
    srv6end: str = ''
    srv6endDT4: str = ''
    srv6local: str = ''
    srv6sid_prefixlen: int = 64
    srv6local_prefixlen: int = 48
    vrf_announce: bool = True

    def __post_init__(self):
        self.vrf_ifname = f'vrf-{self.vrf_table}'
        self.br_ifname = f'br-{self.vrf_table}'
        self.vxlan_ifname = f'vxlan-{self.l2vni}'


@dataclass
class NamespaceDomain:
    vrf: int
    l2vni: int
    l3vni: int
    namespaces: set[str]
    prefixes: list[IPv4Network]


class VRFRegistry:
    def __init__(self) -> None:
        self._vrfs: dict[tuple[int, int], NamespaceDomain] = {}
        self._namespace_domains: dict[str, tuple[int, int]] = {}

    def add(
        self,
        vrf_table: int,
        l2vni: int,
        l3vni: int,
        namespace: str,
        prefix: IPv4Network,
    ) -> bool:
        key = (vrf_table, l2vni)
        existing_key = self._namespace_domains.get(namespace)
        if existing_key is not None and existing_key != key:
            raise ValueError(
                f'namespace {namespace} moved from {existing_key} to {key}'
            )
        domain = self._vrfs.get(key)
        if domain is None:
            domain = NamespaceDomain(
                vrf=vrf_table,
                l2vni=l2vni,
                l3vni=l3vni,
                namespaces=set(),
                prefixes=[],
            )
            self._vrfs[key] = domain
        if domain.l3vni != l3vni:
            raise ValueError(
                f'{namespace} l3vni mismatch: {domain.l3vni} != {l3vni}'
            )
        domain.namespaces.add(namespace)
        self._namespace_domains[namespace] = key
        if prefix not in domain.prefixes:
            domain.prefixes.append(prefix)
        return len(domain.namespaces) == 1

    def remove(self, vrf_table: int, l2vni: int, namespace: str) -> bool:
        key = (vrf_table, l2vni)
        domain = self._vrfs.get(key)
        if domain is None:
            return False
        domain.namespaces.discard(namespace)
        self._namespace_domains.pop(namespace, None)
        if domain.namespaces:
            return False
        del self._vrfs[key]
        return True

    def get(self, vrf_table: int, l2vni: int) -> NamespaceDomain | None:
        return self._vrfs.get((vrf_table, l2vni))

    def clear(self) -> None:
        self._vrfs.clear()
        self._namespace_domains.clear()


class Plugin(PluginProtocol):
    def __init__(
        self, config: ConfigParser, address_pool: AddressPool
    ) -> None:
        self.config = config
        self.address_pool = address_pool
        self.firewall = FirewallManager(config)
        self.vrfs = VRFRegistry()
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

    async def ensure_system_firewall(self, namespace: str) -> None:
        await self.firewall.setup()
        await self.firewall.ensure_system_firewall(namespace)

    async def ensure_segment(
        self,
        namespace: str,
        request: CNIRequest | None = None,
        mask: int = 0xFFFFFFFF,
    ) -> SegmentInfo:
        raise RuntimeError('disabled path')
        config = self.config
        pod_uid: str | None = None
        pod_name: str | None = None
        net_ns_fd: int = 0
        if request is not None:
            pod_uid = get_pod_tag(request, 'uid')
            pod_name = get_pod_tag(request, 'name')
            net_ns_fd = request.netns
        info = await self.allocate_segment(
            namespace, config, pod_uid, pod_name, net_ns_fd
        )
        template = Template(config['topology']['template'])
        topology = template.substitute(asdict(info))
        logging.info(f'topology\n{topology}')

        if net_ns_fd > 0:
            async with AsyncIPRoute(netns=net_ns_fd) as ipr:
                info.veth_mac = (await ipr.link('get', ifname='eth0'))[0].get(
                    'address'
                )
                logging.info(f'info: {asdict(info)}')

        return info

    async def allocate_segment(
        self,
        namespace: str,
        config: ConfigParser,
        pod_uid: None | str = None,
        pod_name: None | str = None,
        net_ns_fd: int = 0,
    ) -> SegmentInfo:
        raise RuntimeError('disabled path')
        namespace_annotations = get_namespace_annotations(namespace)
        async with AsyncIPRoute() as ipr_main:
            if 'host_if' in config['network']:
                host_ifname = config['network']['host_if']
                logging.info(f'using host_if from config: {host_ifname}')
                (host_link,) = await ipr_main.link_lookup(host_ifname)
                addr_dump = [
                    x
                    async for x in await ipr_main.addr('dump', index=host_link)
                ]
                for msg in addr_dump:
                    host_src = msg.get('address')
                    break
                else:
                    logging.error('could not find host_src')
                    raise Exception()
            else:
                logging.info('trying to calculate host_if')
                default_route = await ipr_main.route('get', dst='1.1.1.1')
                host_link = (default_route[0].get('oif'),)
                host_src = default_route[0].get('prefsrc') or '127.0.0.1'
                host_ifname = (await ipr_main.link('get', index=host_link))[
                    0
                ].get('ifname')
            host_order = host_src.split('.')[-1]
            info = SegmentInfo(
                prefix=namespace_annotations.get(
                    'pyroute2.org/prefix', config['default']['prefix']
                ),
                prefixlen=int(
                    namespace_annotations.get(
                        'pyroute2.org/prefixlen',
                        config['default']['prefixlen'],
                    )
                ),
                vrf_table=int(
                    namespace_annotations.get(
                        'pyroute2.org/vrf', config['default']['vrf']
                    )
                ),
                l2vni=int(
                    namespace_annotations.get(
                        'pyroute2.org/l2vni', config['default']['l2vni']
                    )
                ),
                l3vni=int(
                    namespace_annotations.get(
                        'pyroute2.org/l3vni', config['default']['l3vni']
                    )
                ),
                host_link=host_link,
                host_ifname=host_ifname,
                host_order=host_order,
                namespace=namespace,
                net_ns_fd=net_ns_fd,
                host_ipaddr=config['network']['ipaddr'],
            )
            srv6end = Template(
                namespace_annotations.get(
                    'pyroute2.org/srv6end', config['default']['srv6end']
                )
            )
            info.srv6end = srv6end.substitute(asdict(info))
            srv6endDT4 = Template(
                namespace_annotations.get(
                    'pyroute2.org/srv6endDT4', config['default']['srv6endDT4']
                )
            )
            info.srv6endDT4 = srv6endDT4.substitute(asdict(info))
            srv6local = Template(
                namespace_annotations.get(
                    'pyroute2.org/srv6local', config['default']['srv6local']
                )
            )
            info.srv6local = srv6local.substitute(asdict(info))
            async for _ in await ipr_main.route('dump', dst=info.srv6endDT4):
                info.vrf_announce = False
            network = IPv4Network(f'{info.prefix}/{info.prefixlen}')
            if pod_uid is not None:
                address = await self.address_pool.allocate(
                    network=network,
                    vrf_table=info.vrf_table,
                    l2vni=info.l2vni,
                    pod_uid=pod_uid,
                )
                info.veth_ipaddr = f'{address}/{info.prefixlen}'
                info.pod_name = pod_name or ''

            # reconcile the bridge anyways
            dump_link = [
                x
                async for x in await ipr_main.link(
                    'dump', ifname=info.br_ifname
                )
            ]
            for bridge in dump_link:
                dump_addr = [
                    x
                    async for x in await ipr_main.addr(
                        'dump', family=socket.AF_INET, index=bridge['index']
                    )
                ]
                for msg in dump_addr:
                    info.br_ipaddr = f'{msg.get("address")}/{info.prefixlen}'
                    break
            if not info.br_ipaddr:
                address = await self.address_pool.allocate(
                    network=network,
                    vrf_table=info.vrf_table,
                    l2vni=info.l2vni,
                    is_gateway=True,
                )
                info.br_ipaddr = f'{address}/{info.prefixlen}'
            logging.info(f'bridge {info.br_ifname} addr: {info.br_ipaddr}')

        return info

    async def resync(self) -> None:
        return
        config = self.config
        self.vrfs.clear()

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
        # for domain in []:
        #    if domain.network is not None:
        #        networks.add(
        #            (domain.network, domain.vrf, domain.l2vni, domain.l3vni)
        #        )
        # for ns in v1.list_namespace().items:
        #    metadata = ns.metadata
        #    if metadata is None or metadata.name is None:
        #        continue
        #    await self.ensure_system_firewall(metadata.name)
        #    annotations = metadata.annotations or {}
        #    vrf_table_raw = annotations.get('pyroute2.org/vrf')
        #    if vrf_table_raw is None:
        #        continue
        #    prefix = annotations.get('pyroute2.org/prefix') or default_prefix
        #    prefixlen = (
        #        annotations.get('pyroute2.org/prefixlen') or default_prefixlen
        #    )
        #    vrf_table_int = int(vrf_table_raw)
        #    l2vni = int(annotations.get('pyroute2.org/l2vni', default_l2vni))
        #    l3vni = int(annotations.get('pyroute2.org/l3vni', default_l3vni))
        #    network = IPv4Network(f'{prefix}/{prefixlen}')
        #    networks.add((network, vrf_table_int, l2vni, l3vni))
        #    self.vrfs.add(vrf_table_int, l2vni, l3vni, metadata.name, network)
        #    await self.ensure_segment(metadata.name, mask=1)

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
        await self.ensure_system_firewall(namespace)

        data['interfaces'] = [
            {
                'name': 'eth0',
                'mac': info.veth_mac,
                'sandbox': request.env['CNI_NETNS'],
            }
        ]
        data['ips'] = [
            {
                'address': info.veth_ipaddr,
                'interface': 0,
                'gateway': info.br_ipaddr,
            }
        ]
        data['routes'] = [{'dst': '0.0.0.0/0'}]
        os.close(request.netns)
        logging.info(f'response: {data}')
        return data
