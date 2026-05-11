import asyncio
import errno
import logging
import os
import socket
from configparser import ConfigParser
from dataclasses import asdict, dataclass
from ipaddress import IPv4Network
from pathlib import Path
from string import Template
from typing import Any

from pyroute2 import AsyncIPRoute, NetlinkError, Plan9ServerSocket
from sdn_fixtures.main import ensure

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.firewall import FirewallManager
from pyroute2_cni.kubernetes import get_namespace_labels, get_pod_tag
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
    vxlan_id: int
    host_link: int
    host_ifname: str
    host_order: int
    namespace: str
    net_ns_fd: int = 0
    veth_ipaddr: str = ''
    br_ipaddr: str = ''
    vrf_ifname: str = ''
    br_ifname: str = ''
    vxlan_ifname: str = ''
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
        self.vxlan_ifname = f'vxlan-{self.vxlan_id}'


@dataclass(frozen=True)
class VRFEntry:
    vrf: str
    vni: int


class VRFRegistry:
    def __init__(self) -> None:
        self._vrfs: dict[tuple[int, int], VRFEntry] = {}

    def add(self, vrf_table: int, vxlan_id: int) -> bool:
        key = (vrf_table, vxlan_id)
        if key in self._vrfs:
            return False
        self._vrfs[key] = VRFEntry(vrf=f'vrf-{vrf_table}', vni=vxlan_id)
        return True

    def items(self) -> list[VRFEntry]:
        return list(self._vrfs.values())


class FRRManager:
    def __init__(self, template_path: str, config: ConfigParser) -> None:
        self.template_path = Path(template_path)
        self.config = config
        self.output_path = Path('/etc/frr/frr.conf')
        self.reload_sock = '/var/run/frr/reload.sock'

    def render(
        self,
        vrfs: list[VRFEntry],
        all_peer_ips: list[str],
        control_plane_peer_ips: list[str],
        is_control_plane: bool,
    ) -> str:
        vrf_sections = []
        vrf_router_sections = []
        for item in vrfs:
            vrf_sections.append(f'vrf {item.vrf}\n vni {item.vni}\nexit-vrf')
            vrf_router_sections.append(
                f'router bgp 65000 vrf {item.vrf}\n'
                f' !\n'
                f' address-family ipv4 unicast\n'
                f'  redistribute connected\n'
                f'  redistribute static\n'
                f'  redistribute kernel\n'
                f' exit-address-family\n'
                f' !\n'
                f' address-family l2vpn evpn\n'
                f'  advertise ipv4 unicast\n'
                f' exit-address-family\n'
                f'exit'
            )

        peer_sections = '\n'.join(
            f' neighbor {peer} peer-group RR' for peer in all_peer_ips
        )
        rr_sections = ''
        if is_control_plane:
            rr_sections = '  bgp cluster-id 65000\n'
            rr_sections += '\n'.join(
                f'  neighbor {peer} route-reflector-client'
                for peer in control_plane_peer_ips
            )

        template = Template(self.template_path.read_text(encoding='utf-8'))
        return template.substitute(
            node_name=self.config['network']['node_name'],
            router_id=self.config['network']['ipaddr'],
            peer_sections=peer_sections,
            rr_sections=rr_sections,
            vrf_sections='\n!\n'.join(vrf_sections),
            vrf_router_sections='\n!\n'.join(vrf_router_sections),
        )

    async def reload(
        self,
        vrfs: list[VRFEntry],
        all_peer_ips: list[str],
        control_plane_peer_ips: list[str],
        is_control_plane: bool,
    ) -> None:
        self.output_path.write_text(
            self.render(
                vrfs, all_peer_ips, control_plane_peer_ips, is_control_plane
            ),
            encoding='utf-8',
        )
        reader, writer = await asyncio.open_unix_connection(self.reload_sock)
        try:
            writer.write(b'restart\n')
            await writer.drain()
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()


class Plugin(PluginProtocol):
    def __init__(self, config: ConfigParser) -> None:
        self.config = config
        self.frr = FRRManager('/pyroute2-cni/templates/frr.conf.tpl', config)
        self.firewall = FirewallManager(config)
        self.vrfs = VRFRegistry()
        self.all_peer_ips: list[str] = []
        self.control_plane_peer_ips: list[str] = []
        self.is_control_plane = False

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

    @staticmethod
    def _is_control_plane_node(node: Any) -> bool:
        labels = node.metadata.labels or {}
        return (
            'node-role.kubernetes.io/control-plane' in labels
            or 'node-role.kubernetes.io/master' in labels
        )

    def refresh_frr_peers(self, v1: k8s_client.CoreV1Api) -> None:
        all_peer_ips = []
        control_plane_peer_ips = []
        local_node_name = self.config['network']['node_name']
        for node in v1.list_node().items:
            if node.metadata and node.metadata.name == local_node_name:
                continue
            peer_ip = self._node_peer_ip(node)
            if peer_ip is None:
                continue
            all_peer_ips.append(peer_ip)
            if self._is_control_plane_node(node):
                control_plane_peer_ips.append(peer_ip)
        self.all_peer_ips = sorted(set(all_peer_ips))
        self.control_plane_peer_ips = sorted(set(control_plane_peer_ips))
        self.is_control_plane = bool(self.control_plane_peer_ips)

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
        await self.firewall.ensure_system_firewall(namespace)

    async def ensure_segment(
        self,
        namespace: str,
        pool: AddressPool,
        request: None | CNIRequest = None,
        mask: int = 0xFFFFFFFF,
        p9server: None | Plan9ServerSocket = None,
    ) -> SegmentInfo:
        config = self.config
        pod_uid: None | str = None
        pod_name: None | str = None
        net_ns_fd: None | int = 0
        max_attempts: int = 5
        has_vrf: bool = False
        if request is not None:
            pod_uid = get_pod_tag(request, 'uid')
            pod_name = get_pod_tag(request, 'name')
            net_ns_fd = request.netns
        info = await self.allocate_segment(
            namespace, pool, config, pod_uid, pod_name, net_ns_fd
        )
        if self.frr is not None and self.vrfs.add(
            info.vrf_table, info.vxlan_id
        ):
            await self.frr.reload(
                self.vrfs.items(),
                self.all_peer_ips,
                self.control_plane_peer_ips,
                self.is_control_plane,
            )
        template = Template(config['topology']['template'])
        topology = template.substitute(asdict(info))
        logging.info(f'topology\n{topology}')
        if request is not None and p9server is not None:
            base: str = f'segments/{namespace}'
            try:
                p9server.filesystem.walk(base)
            except KeyError:
                p9server.filesystem.create(base, qtype=0x80)
            with p9server.filesystem.create(f'{base}/{pod_name}.dot') as i:
                i.data.write(topology.encode('utf-8'))
        attempts = max_attempts
        while attempts:
            attempts -= 1
            try:
                await ensure(present=True, data=topology, mask=mask)
                async with AsyncIPRoute() as ipr:
                    table = 254
                    service_vrf_max = (
                        int(config['default']['service_vrf_max']) or 1024
                    )
                    if info.vrf_table > service_vrf_max:
                        table = info.vrf_table
                    await self.reconcile_routes(
                        ipr,
                        pool.block_cidrs(
                            IPv4Network(f'{info.prefix}/{info.prefixlen}'),
                            info.vrf_table,
                            info.vxlan_id,
                        ),
                        info.br_ifname,
                        table,
                    )
                    if not has_vrf and await ipr.link_lookup(info.vrf_ifname):
                        has_vrf = True

                if net_ns_fd > 0:
                    async with AsyncIPRoute(netns=net_ns_fd) as ipr:
                        info.veth_mac = (await ipr.link('get', ifname='eth0'))[
                            0
                        ].get('address')
                        logging.info(f'info: {asdict(info)}')
                        await ipr.route('add', gateway=info.br_ipaddr)
            except NetlinkError as e:
                if e.code == errno.EBUSY:
                    await asyncio.sleep(1)
                    continue
                raise

            set_sysctl(
                {
                    'net.ipv6.conf.all.seg6_enabled': 1,
                    f'net.ipv6.conf.{info.host_ifname}.seg6_enabled': 1,
                    'net.ipv4.conf.all.rp_filter': 0,  # asymmetric SRv6
                }
            )
            if has_vrf:
                set_sysctl(
                    {
                        'net.vrf.strict_mode': 1,  # SRv6 End.DT4
                        f'net.ipv4.conf.{info.vrf_ifname}.rp_filter': 0,
                        'net.ipv4.tcp_l3mdev_accept': 1,  # serve cross VRF
                        'net.ipv4.udp_l3mdev_accept': 1,  # serve cross VRF
                    }
                )
            break
        else:
            raise TimeoutError('could not ensure the segment')

        attempts = max_attempts
        while attempts:
            attempts -= 1
            try:
                async with AsyncIPRoute() as ipr:
                    if info.vrf_announce and info.srv6endDT4:
                        await ipr.route(
                            'replace',
                            dst=info.srv6endDT4,
                            dst_len=128,
                            oif=await ipr.link_lookup(info.vrf_ifname),
                            encap={
                                'type': 'seg6local',
                                'action': 'End.DT4',
                                'vrf_table': info.vrf_table,
                            },
                        )
                        try:
                            with open('/var/run/exabgp/exabgp.in', 'w') as f:
                                cmd = f'announce route {info.srv6endDT4}/128 '
                                cmd += f'next-hop {info.srv6local}\n'
                                f.write(cmd)
                        except (FileNotFoundError, PermissionError):
                            pass
                        await ipr.ensure(
                            ipr.addr,
                            present=True,
                            index=info.host_link,
                            address=info.srv6local,
                            prefixlen=info.srv6local_prefixlen,
                        )
            except NetlinkError as e:
                if e.code in (errno.EBUSY, errno.EPERM):
                    await asyncio.sleep(1)
                    continue
                raise
            break
        else:
            raise TimeoutError('could not ensure SRv6')
        return info

    async def allocate_segment(
        self,
        namespace: str,
        pool: AddressPool,
        config: ConfigParser,
        pod_uid: None | str = None,
        pod_name: None | str = None,
        net_ns_fd: int = 0,
    ) -> SegmentInfo:
        labels = get_namespace_labels(namespace)
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
                prefix=labels.get(
                    'pyroute2.org/prefix', config['default']['prefix']
                ),
                prefixlen=int(
                    labels.get(
                        'pyroute2.org/prefixlen',
                        config['default']['prefixlen'],
                    )
                ),
                vrf_table=int(
                    labels.get('pyroute2.org/vrf', config['default']['vrf'])
                ),
                vxlan_id=int(
                    labels.get(
                        'pyroute2.org/vxlan', config['default']['vxlan']
                    )
                ),
                host_link=host_link,
                host_ifname=host_ifname,
                host_order=host_order,
                namespace=namespace,
                net_ns_fd=net_ns_fd,
            )
            srv6end = Template(
                labels.get(
                    'pyroute2.org/srv6end', config['default']['srv6end']
                )
            )
            info.srv6end = srv6end.substitute(asdict(info))
            srv6endDT4 = Template(
                labels.get(
                    'pyroute2.org/srv6endDT4', config['default']['srv6endDT4']
                )
            )
            info.srv6endDT4 = srv6endDT4.substitute(asdict(info))
            srv6local = Template(
                labels.get(
                    'pyroute2.org/srv6local', config['default']['srv6local']
                )
            )
            info.srv6local = srv6local.substitute(asdict(info))
            async for _ in await ipr_main.route('dump', dst=info.srv6endDT4):
                info.vrf_announce = False
            network = IPv4Network(f'{info.prefix}/{info.prefixlen}')
            if pod_uid is not None:
                address = await pool.allocate(
                    network=network,
                    vrf_table=info.vrf_table,
                    vxlan_id=info.vxlan_id,
                    pod_uid=pod_uid,
                )
                info.veth_ipaddr = f'{address}/{info.prefixlen}'
                info.pod_name = pod_name

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
                address = await pool.allocate(
                    network=network,
                    vrf_table=info.vrf_table,
                    vxlan_id=info.vxlan_id,
                    is_gateway=True,
                )
                info.br_ipaddr = f'{address}/{info.prefixlen}'
            logging.info(f'bridge {info.br_ifname} addr: {info.br_ipaddr}')

        return info

    async def resync(self, address_pool: AddressPool) -> None:
        config = self.config

        # trigger the VRF module
        async with AsyncIPRoute() as ipr_main:
            (vrf1,) = await ipr_main.ensure(
                ipr_main.link,
                present=True,
                ifname='vrf-1',
                kind='vrf',
                vrf_table=1,
            )
            await ipr_main.ensure(
                ipr_main.link, present=False, index=vrf1['index']
            )

        await self.ensure_segment('kube-system', address_pool, mask=1)

        # 1. list network namespaces -> bridges & vxlan
        try:
            k8s_config.load_incluster_config()
        except Exception as e:
            logging.error(f'error listing namespaces: {e}')
            return

        v1 = k8s_client.CoreV1Api()
        self.refresh_frr_peers(v1)
        node_name = address_pool.node_name
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
        default_vxlan = int(config['default']['vxlan'])
        networks.add(
            (
                IPv4Network(f'{default_prefix}/{default_prefixlen}'),
                default_vrf,
                default_vxlan,
            )
        )
        for ns in v1.list_namespace().items:
            await self.ensure_system_firewall(ns.metadata.name)
            labels = ns.metadata.labels or {}
            vrf_table = labels.get('pyroute2.org/vrf')
            if vrf_table is None:
                continue
            prefix = labels.get('pyroute2.org/prefix') or default_prefix
            prefixlen = (
                labels.get('pyroute2.org/prefixlen') or default_prefixlen
            )
            vrf_table = int(vrf_table)
            vxlan_id = int(labels.get('pyroute2.org/vxlan', default_vxlan))
            network = IPv4Network(f'{prefix}/{prefixlen}')
            networks.add((network, vrf_table, vxlan_id))
            self.vrfs.add(vrf_table, vxlan_id)

        for network, vrf_table, vxlan_id in networks:
            br_ifname = f'br-{vrf_table}'
            gateway_ip = None
            async with AsyncIPRoute() as ipr:
                block_cidrs = address_pool.block_cidrs(
                    network, vrf_table, vxlan_id
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
                    await address_pool.allocate(
                        network=network,
                        vrf_table=vrf_table,
                        vxlan_id=vxlan_id,
                        is_gateway=True,
                        address=address_pool.inet_aton(network, gateway_ip),
                    )
                    await address_pool.prune_stale_allocations(
                        network, vrf_table, vxlan_id, live_pod_ips, gateway_ip
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

        await address_pool.gc_empty_blocks()
        if self.frr is not None:
            await self.frr.reload(
                self.vrfs.items(),
                self.all_peer_ips,
                self.control_plane_peer_ips,
                self.is_control_plane,
            )

    async def cleanup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        p9server: Plan9ServerSocket,
    ) -> dict[str, Any]:
        '''
        Run network cleanup
        '''
        pod_uid = get_pod_tag(request, 'uid')
        try:
            await pool.release(pod_uid)
        except KeyError:
            # just ignore non existent addresses for now
            logging.error(f'pod_uid {pod_uid} not registered')
        try:
            await pool.gc_empty_blocks()
        except Exception as e:
            logging.warning(f'empty IPBlock gc failed: {e}')
        return data

    async def setup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        p9server: Plan9ServerSocket,
    ) -> dict[str, Any]:
        '''
        Run network setup
        '''
        await request.ready()
        logging.info(f'request {request.rid} ready')

        namespace = get_pod_tag(request, 'namespace', default='default')
        info = await self.ensure_segment(
            namespace, pool, request, p9server=p9server
        )
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
