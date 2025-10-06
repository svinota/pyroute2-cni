import base64
import logging
import os
import socket
import struct
from configparser import ConfigParser
from dataclasses import asdict, dataclass
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from string import Template
from typing import Any

from pyroute2 import AsyncIPRoute
from pyroute2.netlink.nfnetlink.nftsocket import Cmp, Meta, Regs
from pyroute2.nftables.expressions import genex, ipv4addr, masq
from pyroute2.nftables.main import AsyncNFTables
from sdn_fixtures.main import ensure

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest


def set_sysctl(config: dict[str, int]) -> None:
    for path, value in config.items():
        with open(f'/proc/sys/{path.replace(".", "/")}', 'w') as f:
            f.write(str(value))


def get_namespace_labels(name: str) -> dict[str, str]:
    try:
        k8s_config.load_incluster_config()
    except Exception as e:
        logging.error(f'error C reading namespace {name}: {e}')
        return {}
    v1 = k8s_client.CoreV1Api()
    try:
        ns = v1.read_namespace(name=name)
    except Exception as e:
        logging.error(f'error R reading namespace {name}: {e}')
        return {}
    # except kubernetes.client.exceptions.ApiException:
    #    return {}
    return ns.metadata.labels or {}


def get_pod_tag(request: CNIRequest, tag: str, default: str = '') -> str:
    cni_args = request.env.get('CNI_ARGS', '')
    for arg in cni_args.split(';'):
        key, value = arg.split('=')
        if key == f'K8S_POD_{tag.upper()}':
            return value
    logging.warning('got no pod namespace, return default')
    return default


def oif(index):
    ret = []
    ret.append(
        genex('meta', {'key': Meta.NFT_META_OIF, 'dreg': Regs.NFT_REG_1})
    )
    ret.append(
        genex(
            'cmp',
            {
                'sreg': Regs.NFT_REG_1,
                'op': Cmp.NFT_CMP_EQ,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', index)]]
                },
            },
        )
    )
    return ret


@dataclass
class SegmentInfo:
    prefix: str
    prefixlen: int
    vrf_table: int
    vxlan_id: int
    host_link: int
    host_ifname: str
    namespace: str
    net_ns_fd: int = 0
    veth_ipaddr: str = ''
    br_ipaddr: str = ''
    vrf_ifname: str = ''
    br_ifname: str = ''
    vxlan_ifname: str = ''
    veth_mac: str = ''

    def __post_init__(self):
        self.vrf_ifname = f'vrf-{self.vrf_table}'
        self.br_ifname = f'br-{self.vrf_table}'
        self.vxlan_ifname = f'vxlan-{self.vxlan_id}'


class Plugin(PluginProtocol):
    async def ensure_system_firewall(
        self, namespace: str, config: ConfigParser
    ) -> None:
        labels = get_namespace_labels(namespace)
        prefixlen = labels.get(
            'pyroute2.org/prefixlen', config['default']['prefixlen']
        )
        prefix = labels.get('pyroute2.org/prefix', config['default']['prefix'])
        async with AsyncIPRoute() as ipr_main:
            default_route = await ipr_main.route('get', dst='1.1.1.1')
            default_link = default_route[0].get('oif')
        async with AsyncNFTables() as nft_main:
            # reconcile table
            async for table in await nft_main.get_tables():
                if table.get('name') == 'nat':
                    break
            else:
                await nft_main.table('add', name='nat')

            # reconcile chain
            async for chain in await nft_main.get_chains():
                if chain.get('name') == 'POSTROUTING':
                    break
            else:
                await nft_main.chain(
                    'add',
                    table='nat',
                    name='POSTROUTING',
                    hook='postrouting',
                    type='nat',
                    policy=1,
                )

            # reconcile rule
            magic = '0x42 ' + base64.b64encode(
                f'{prefix}/{prefixlen}'.encode('ascii')
            ).decode('ascii')
            async for rule in await nft_main.get_rules():
                if rule.get('userdata') == magic:
                    break
            else:
                await nft_main.rule(
                    'add',
                    table='nat',
                    chain='POSTROUTING',
                    expressions=(
                        ipv4addr(src=f'{prefix}/{prefixlen}'),
                        ipv4addr(
                            dst=f'{prefix}/{prefixlen}', op=Cmp.NFT_CMP_NEQ
                        ),
                        oif(default_link),
                        masq(),
                    ),
                    userdata=magic,
                )

    async def ensure_segment(
        self,
        namespace: str,
        pool: AddressPool,
        config: ConfigParser,
        pod_uid: None | str = None,
        net_ns_fd: int = 0,
        mask: int = 0xFFFFFFFF,
    ) -> SegmentInfo:
        info = await self.allocate_segment(
            namespace, pool, config, pod_uid, net_ns_fd
        )
        template = Template(config['topology']['template'])
        topology = template.substitute(asdict(info))
        logging.info(f'topology\n{topology}')
        await ensure(present=True, data=topology, mask=mask)
        async with AsyncIPRoute() as ipr:
            await ipr.route(
                'replace',
                dst=info.prefix,
                dst_len=info.prefixlen,
                oif=await ipr.link_lookup(info.br_ifname),
            )

        if net_ns_fd > 0:
            async with AsyncIPRoute(netns=net_ns_fd) as ipr:
                info.veth_mac = (await ipr.link('get', ifname='eth0'))[0].get(
                    'address'
                )
                logging.info(f'info: {asdict(info)}')
                await ipr.route('add', gateway=info.br_ipaddr)

        set_sysctl(
            {
                'net.ipv6.conf.all.seg6_enabled': 1,
                f'net.ipv6.conf.{info.host_ifname}.seg6_enabled': 1,
                'net.ipv4.conf.all.rp_filter': 0,  # <-- asymmetric SRv6
                'net.vrf.strict_mode': 1,  # <-- required for SRv6 End.DT4
            }
        )
        set_sysctl(
            {
                f'net.ipv4.conf.{info.vrf_ifname}.rp_filter': 0,  # <-- SRv6
                'net.ipv4.tcp_l3mdev_accept': 1,  # <-- serve cross VRF
                'net.ipv4.udp_l3mdev_accept': 1,  # <-- serve cross VRF
            }
        )
        return info

    async def allocate_segment(
        self,
        namespace: str,
        pool: AddressPool,
        config: ConfigParser,
        pod_uid: None | str = None,
        net_ns_fd: int = 0,
    ) -> SegmentInfo:
        labels = get_namespace_labels(namespace)
        async with AsyncIPRoute() as ipr_main:
            default_route = await ipr_main.route('get', dst='1.1.1.1')
            host_link = (default_route[0].get('oif'),)
            host_ifname = (await ipr_main.link('get', index=host_link))[0].get(
                'ifname'
            )
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
                namespace=namespace,
                net_ns_fd=net_ns_fd,
            )
            if pod_uid is not None:
                network = IPv4Network(f'{info.prefix}/{info.prefixlen}')
                address = await pool.allocate(network=network, pod_uid=pod_uid)
                info.veth_ipaddr = f'{address}/{info.prefixlen}'
                async for bridge in await ipr_main.link(
                    'dump', ifname=info.br_ifname
                ):
                    async for address in await ipr_main.addr(
                        'dump', family=socket.AF_INET, index=bridge['index']
                    ):
                        info.br_ipaddr = address.get('address')
                        break
                if not info.br_ipaddr:
                    info.br_ipaddr = await pool.allocate(
                        network=network, is_gateway=True
                    )

        return info

    async def resync(
        self, address_pool: AddressPool, config: ConfigParser
    ) -> None:

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

        await self.ensure_segment('kube-system', address_pool, config, mask=1)

        # 1. list network namespaces -> bridges & vxlan
        # 2. list pods -> addresses
        try:
            k8s_config.load_incluster_config()
        except Exception as e:
            logging.error(f'error listing namespaces: {e}')
            return

        v1 = k8s_client.CoreV1Api()
        networks = set()
        default_prefix = config['default']['prefix']
        default_prefixlen = config['default']['prefixlen']
        default_vrf = config['default']['vrf']
        host_ip = config['network']['ipaddr']
        logging.info(f'host ip: {host_ip}')
        networks.add(
            (IPv4Network(f'{default_prefix}/{default_prefixlen}'), default_vrf)
        )
        for ns in v1.list_namespace().items:
            labels = ns.metadata.labels or {}
            vrf_table = labels.get('pyroute2.org/vrf')
            if vrf_table is None:
                continue
            prefix = labels.get('pyroute2.org/prefix')
            if prefix is None:
                continue
            prefixlen = labels.get('pyroute2.org/prefixlen')
            if prefixlen is None:
                continue
            vrf_table = int(vrf_table)
            network = IPv4Network(f'{prefix}/{prefixlen}')
            networks.add((network, vrf_table))

        for network, vrf_table in networks:
            br_ifname = f'br-{vrf_table}'
            async with AsyncIPRoute() as ipr:
                br_idx = await ipr.link_lookup(ifname=br_ifname)
                if not br_idx:
                    continue
                bridge_addr = [
                    x
                    async for x in await ipr.addr(
                        'dump', family=socket.AF_INET, index=br_idx[0]
                    )
                ]
                if not bridge_addr:
                    continue
                await address_pool.allocate(
                    network=network,
                    is_gateway=True,
                    address=address_pool.inet_aton(
                        network, bridge_addr[0].get('address')
                    ),
                )

        for pod in v1.list_pod_for_all_namespaces().items:
            if pod.status.host_ip != host_ip:
                continue
            try:
                for network, _ in networks:
                    if IPv4Address(pod.status.pod_ip) in network:
                        await address_pool.allocate(
                            network=network,
                            is_gateway=False,
                            address=address_pool.inet_aton(
                                network, pod.status.pod_ip
                            ),
                            pod_uid=pod.metadata.uid,
                        )
            except AddressValueError:
                pass

    async def cleanup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        config: ConfigParser,
    ) -> dict[str, Any]:
        '''
        Run network setup
        '''
        pod_uid = get_pod_tag(request, 'uid')
        try:
            await pool.release(pod_uid)
        except KeyError:
            # just ignore non existent addresses for now
            logging.error(f'container {pod_uid} not registered')
        return data

    async def setup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        config: ConfigParser,
    ) -> dict[str, Any]:
        '''
        Run network setup
        '''
        await request.ready()
        logging.info(f'request {request.rid} ready')

        namespace = get_pod_tag(request, 'namespace', default='default')
        pod_uid = get_pod_tag(request, 'uid')
        info = await self.ensure_segment(
            namespace, pool, config, pod_uid, request.netns
        )
        await self.ensure_system_firewall(namespace, config)

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
