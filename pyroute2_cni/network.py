import logging
import os
import socket
from configparser import ConfigParser
from ipaddress import AddressValueError, IPv4Address, IPv4Network
from typing import Any

from pyroute2 import AsyncIPRoute
from pyroute2.common import uifname

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


class Plugin(PluginProtocol):
    async def resync(
        self, address_pool: AddressPool, config: ConfigParser
    ) -> None:
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
            br_name = f'br-{vrf_table}'
            async with AsyncIPRoute() as ipr:
                br_idx = await ipr.link_lookup(ifname=br_name)
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

        vp0 = uifname()

        ###
        # get VRF and VXLAN ids for this container
        #
        namespace = get_pod_tag(request, 'namespace', default='default')
        labels = get_namespace_labels(namespace)
        vrf_table = int(
            labels.get('pyroute2.org/vrf', config['default']['vrf'])
        )
        vxlan_id = int(
            labels.get('pyroute2.org/vxlan', config['default']['vxlan'])
        )
        prefixlen = int(
            labels.get(
                'pyroute2.org/prefixlen', config['default']['prefixlen']
            )
        )
        prefix = labels.get('pyroute2.org/prefix', config['default']['prefix'])
        network = IPv4Network(f'{prefix}/{prefixlen}')

        async with AsyncIPRoute() as ipr_main:
            default_route = await ipr_main.route('get', dst='1.1.1.1')
            host_link = default_route[0].get('oif')
            host_if = (await ipr_main.link('get', index=host_link))[0].get(
                'ifname'
            )
            set_sysctl(
                {
                    'net.ipv6.conf.all.seg6_enabled': 1,
                    f'net.ipv6.conf.{host_if}.seg6_enabled': 1,
                    'net.ipv4.conf.all.rp_filter': 0,  # <-- asymmetric SRv6
                    'net.vrf.strict_mode': 1,  # <-- required for SRv6 End.DT4
                }
            )
            ###
            # configure vrf
            #
            vrf_name = f'vrf-{vrf_table}'
            if not await ipr_main.link_lookup(ifname=vrf_name):
                await ipr_main.link(
                    'add',
                    ifname=vrf_name,
                    kind='vrf',
                    vrf_table=vrf_table,
                    state='up',
                )
            (vrf,) = await ipr_main.poll(
                ipr_main.link, 'dump', ifname=vrf_name, timeout=5
            )
            set_sysctl(
                {
                    f'net.ipv4.conf.{vrf_name}.rp_filter': 0,  # <-- SRv6
                    'net.ipv4.tcp_l3mdev_accept': 1,  # <-- serve cross VRF
                    'net.ipv4.udp_l3mdev_accept': 1,  # <-- serve cross VRF
                }
            )

            ###
            # configure bridge
            #
            br_name = f'br-{vrf_table}'
            if not await ipr_main.link_lookup(ifname=br_name):
                await ipr_main.link(
                    'add', ifname=br_name, kind='bridge', state='up'
                )
            (bridge,) = await ipr_main.poll(
                ipr_main.link, 'dump', ifname=br_name, timeout=5
            )
            bridge_addr = [
                x
                async for x in await ipr_main.addr(
                    'dump', family=socket.AF_INET, index=bridge['index']
                )
            ]
            if len(bridge_addr):
                gateway = bridge_addr[0].get('address')
            else:
                gateway = await pool.allocate(network=network, is_gateway=True)
                await ipr_main.addr(
                    'add',
                    index=bridge['index'],
                    address=f'{gateway}/{prefixlen}',
                )
            if bridge.get('master') != vrf['index']:
                await ipr_main.link(
                    'set', index=bridge['index'], master=vrf['index']
                )
                # if vrf_table < 100:
                await ipr_main.route(
                    'add', dst=prefix, dst_len=prefixlen, oif=vrf['index']
                )

            ###
            # configure vxlan
            #
            vxlan_name = f'vxlan-{vxlan_id}'
            if not await ipr_main.link_lookup(ifname=vxlan_name):
                await ipr_main.link(
                    'add',
                    ifname=vxlan_name,
                    kind='vxlan',
                    state='up',
                    master=bridge['index'],
                    vxlan_link=host_link,
                    vxlan_id=vxlan_id,
                    vxlan_group='239.1.1.1',
                )

            ###
            # configure veth
            #
            await ipr_main.link(
                'add',
                kind='veth',
                ifname=vp0,
                state='up',
                peer={'ifname': 'eth0', 'net_ns_fd': request.netns},
            )
            (port,) = await ipr_main.poll(
                ipr_main.link, 'dump', ifname=vp0, timeout=5
            )
            await ipr_main.link(
                'set', index=port['index'], master=bridge['index']
            )

        ###
        # configure container's veth
        #
        address = await pool.allocate(
            network=network, pod_uid=get_pod_tag(request, 'uid')
        )
        address = f'{address}/{prefixlen}'
        async with AsyncIPRoute(netns=request.netns) as ipr:
            (eth0,) = await ipr.link('get', ifname='eth0')
            await ipr.link('set', index=eth0['index'], state='up')
            await ipr.addr('add', index=eth0['index'], address=address)
            await ipr.route('add', gateway=gateway)

        data['interfaces'] = [
            {
                'name': 'eth0',
                'mac': eth0.get('address'),
                'sandbox': request.env['CNI_NETNS'],
            }
        ]
        data['ips'] = [
            {'address': address, 'interface': 0, 'gateway': gateway}
        ]
        data['routes'] = [{'dst': '0.0.0.0/0'}]
        os.close(request.netns)
        logging.info(f'response: {data}')
        return data
