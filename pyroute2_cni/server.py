import asyncio
import json
import logging
import os
import platform
import signal
import socket
import struct
import sys
import uuid
from configparser import ConfigParser
from functools import partial
from ipaddress import IPv4Network
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, PrivateAttr, ValidationError
from pyroute2 import AsyncIPRoute, Plan9ServerSocket
from pyroute2.common import uifname
from pyroute2.netlink.nfnetlink.nftsocket import Cmp, Meta, Regs
from pyroute2.nftables.expressions import genex, ipv4addr, masq
from pyroute2.nftables.main import AsyncNFTables

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from pyroute2_cni.address_pool import AddressPool

logging.basicConfig(level=logging.INFO)


class CNIInterface(BaseModel):
    name: str
    mac: str
    sandbox: str | None = None
    gateway: str | None = None


class CNIConfig(BaseModel):
    cniVersion: str
    interfaces: list[CNIInterface] | None = None


class CNIRequest(BaseModel):
    _ready: asyncio.Event = PrivateAttr()
    model_config = ConfigDict(extra="forbid")
    error: str = ''
    errno: int = 0
    cni: CNIConfig = CNIConfig(cniVersion='')
    rid: str | None = None
    netns: int = 0
    env: dict[str, str] = {}

    def __init__(self, **kwarg):
        super().__init__(**kwarg)
        self._ready = asyncio.Event()

    def merge(self, request):
        # just replace for now
        if request.cni is not None:
            self.cni = request.cni
        if request.env is not None:
            self.env = request.env

    async def ready(self):
        await asyncio.wait_for(self._ready.wait(), timeout=5.0)

    def set_ready(self):
        self._ready.set()


class CNIProtocol(asyncio.Protocol):

    transport: asyncio.Transport

    def __init__(
        self,
        on_con_lost: asyncio.Future,
        registry: dict[str, CNIRequest],
        config: ConfigParser,
        address_pool: AddressPool,
    ):
        self.on_con_lost = on_con_lost
        self.registry = registry
        self.pool = address_pool
        self.config = config

    def error(self, spec: str):
        return self.transport.write(spec.encode('utf-8'))

    def data_received(self, data: bytes):
        # we have now two types of requests in the protocol.
        # 1. RID request -> returns request id
        # 2. CNI request -> returns CNI config by RID
        run_setup: bool = True
        try:
            request = CNIRequest.model_validate_json(data)
        except ValidationError as err:
            return self.error(err.json())
        logging.info(f'got request {request}')
        if request.rid is None:
            run_setup = False
            request.rid = str(uuid.uuid4())
            logging.info(f'answer with rid {request.rid}')
            self.transport.write(
                json.dumps({'rid': request.rid}).encode('utf-8')
            )
        if request.rid not in self.registry:
            logging.info(f'register request rid {request.rid}')
            self.registry[request.rid] = request
        else:
            logging.info(f'merge request rid {request.rid}')
            self.registry[request.rid].merge(request)
        if run_setup:
            response: dict[str, Any] = {'cniVersion': request.cni.cniVersion}
            command = request.env.get('CNI_COMMAND', None)

            if command == 'ADD':
                logging.info('cni ready, wait for fd')
                loop = asyncio.get_event_loop()
                loop.create_task(
                    setup_container_network(
                        self.transport,
                        response,
                        self.registry[request.rid],
                        self.pool,
                        self.config,
                    )
                )
            elif command == 'DEL':
                logging.info('running cleanup')
                loop = asyncio.get_event_loop()
                loop.create_task(
                    cleanup_container_network(
                        self.transport,
                        response,
                        self.registry[request.rid],
                        self.pool,
                        self.config,
                    )
                )
            else:
                logging.info(
                    f'return on command {request.env.get("CNI_COMMAND", None)}'
                )
                return cni_response(self.transport, response)

    # do not annotate
    def connection_made(self, transport):
        self.transport = transport


class CNIServer:

    endpoint: asyncio.AbstractServer

    def __init__(
        self,
        config: ConfigParser,
        registry: dict[str, CNIRequest],
        address_pool: AddressPool,
        use_event_loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.event_loop = use_event_loop or asyncio.get_event_loop()
        self.connection_lost = self.event_loop.create_future()
        self.path = config['api']['socket_path_api']
        self.registry = registry
        self.config = config
        self.address_pool = address_pool

    async def setup_endpoint(self):
        self.endpoint = await self.event_loop.create_unix_server(
            lambda: CNIProtocol(
                self.connection_lost,
                self.registry,
                self.config,
                self.address_pool,
            ),
            path=self.path,
        )


def cni_response(transport, data):
    return transport.write(json.dumps(data).encode('utf-8'))


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


async def reconcile_system_firewall(
    pool: AddressPool, host_link: int, magic: str
) -> None:
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
        async for rule in await nft_main.get_rules():
            if rule.get('userdata') == magic:
                break
        else:
            await nft_main.rule(
                'add',
                table='nat',
                chain='POSTROUTING',
                expressions=(
                    ipv4addr(src='10.244.0.0/16'),
                    ipv4addr(dst='10.244.0.0/16', op=Cmp.NFT_CMP_NEQ),
                    masq(),
                ),
                userdata=magic,
            )


async def cleanup_container_network(
    transport: asyncio.BaseTransport,
    data: dict[str, Any],
    request: CNIRequest,
    pool: AddressPool,
    config: ConfigParser,
) -> None:
    '''
    Run network setup
    '''
    containerid = request.env.get('CNI_CONTAINERID', '')
    try:
        await pool.release(containerid)
    except KeyError:
        # just ignore non existent addresses for now
        logging.error(f'container {containerid} not registered')
    cni_response(transport, data)


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


def get_pod_namespace(request: CNIRequest) -> str:
    cni_args = request.env.get('CNI_ARGS', '')
    for arg in cni_args.split(';'):
        key, value = arg.split('=')
        if key == 'K8S_POD_NAMESPACE':
            return value
    logging.warning('got no pod namespace, return default')
    return 'default'


async def setup_container_network(
    transport: asyncio.BaseTransport,
    data: dict[str, Any],
    request: CNIRequest,
    pool: AddressPool,
    config: ConfigParser,
) -> None:
    '''
    Run network setup
    '''
    await request.ready()
    logging.info(f'request {request.rid} ready')

    vp0 = uifname()

    # MUST load vrf module before running CNI!
    set_sysctl(
        {
            'net.ipv6.conf.all.seg6_enabled': 1,
            f'net.ipv6.conf.{config["network"]["host_if"]}.seg6_enabled': 1,
            'net.ipv4.conf.all.rp_filter': 0,  # <-- asymmetric SRv6
            'net.vrf.strict_mode': 1,  # <-- required for SRv6 End.DT4
        }
    )

    ###
    # get VRF and VXLAN ids for this container
    #
    namespace = get_pod_namespace(request)
    labels = get_namespace_labels(namespace)
    vrf_table = int(labels.get('pyroute2.org/vrf', '42'))
    vxlan_id = int(labels.get('pyroute2.org/vxlan', '42'))
    prefixlen = int(labels.get('pyroute2.org/prefixlen', '16'))
    prefix = labels.get('pyroute2.org/network', '10.244.0.0')
    network = IPv4Network(f'{prefix}/{prefixlen}')

    async with AsyncIPRoute() as ipr_main:
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
                'add', index=bridge['index'], address=f'{gateway}/{prefixlen}'
            )
        if bridge.get('master') != vrf['index']:
            await ipr_main.link(
                'set', index=bridge['index'], master=vrf['index']
            )
            # if vrf_table < 100:
            await ipr_main.route(
                'add', dst=prefix, dst_len=prefixlen, oif=vrf['index']
            )

        host_link = tuple(
            await ipr_main.link_lookup(ifname=config['network']['host_if'])
        )[0]
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
        await ipr_main.link('set', index=port['index'], master=bridge['index'])

    await reconcile_system_firewall(
        pool, host_link, config['nftables']['magic']
    )

    ###
    # configure container's veth
    #
    address = await pool.allocate(
        network=network, containerid=request.env.get('CNI_CONTAINERID', '')
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
    data['ips'] = [{'address': address, 'interface': 0, 'gateway': gateway}]
    data['routes'] = [{'dst': '0.0.0.0/0'}]
    os.close(request.netns)
    logging.info(f'response: {data}')
    return cni_response(transport, data)


def cni_request_handler(sock_dgram, registry):
    '''
    Receive JSON CNI config and CNI_NETNS file descriptor.
    '''
    data, ancdata, _, _ = sock_dgram.recvmsg(4096, socket.CMSG_SPACE(4))
    try:
        request = CNIRequest.model_validate_json(data)
    except ValidationError as err:
        logging.error('got ValidationError %s', err)
        return

    if request.rid not in registry:
        logging.info(f'orphan rid {request.rid}')
        return

    if not ancdata:
        logging.info(f'no ancdata for {request.rid}')
        return

    cmsg_level, cmsg_type, packed_fd = ancdata[0]
    if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
        fd = struct.unpack("i", packed_fd)[0]
        logging.info(f'register fd {fd} for {request.rid}')
        registry[request.rid].netns = fd
        registry[request.rid].set_ready()


async def run_fd_receiver(
    registry: dict[str, CNIRequest], socket_path: str
) -> None:
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    server_sock_dgram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server_sock_dgram.bind(socket_path)
    server_sock_dgram.setblocking(False)
    loop = asyncio.get_running_loop()
    loop.add_reader(
        server_sock_dgram, cni_request_handler, server_sock_dgram, registry
    )


def handle_signal(tasks: list[asyncio.Task], signal_num) -> None:
    logging.info(f'got signal {signal.Signals(signal_num).name}')
    for task in tasks:
        task.cancel()


async def main(config: ConfigParser) -> None:
    registry: dict[str, CNIRequest] = {}
    service_ipaddr: str = ''

    async with AsyncIPRoute() as ipr:
        async for route in await ipr.get_default_routes():
            service_ipaddr = route.get('prefsrc')
            break
    config['network']['ipaddr'] = service_ipaddr

    await run_fd_receiver(
        registry, socket_path=config['api']['socket_path_fd']
    )
    service_name = f'{platform.uname().node}.{config["mdns"]["service"]}'
    address_pool = AddressPool(service_name, config)
    cni_server = CNIServer(config, registry, address_pool)
    await cni_server.setup_endpoint()

    p9_server = Plan9ServerSocket(
        address=(service_ipaddr, int(config['plan9']['port']))
    )
    with p9_server.filesystem.create('registry') as i:
        i.metadata.call_on_read = True
        i.register_function(
            lambda: registry,
            loader=lambda x: {},
            dumper=lambda x: json.dumps(
                {k: v.model_dump() for k, v in x.items()}
            ).encode('utf-8'),
        )
    with p9_server.filesystem.create('register_address') as i:
        i.register_function(
            address_pool.register_address, dumper=lambda x: b'{}'
        )
    with p9_server.filesystem.create('unregister_address') as i:
        i.register_function(
            address_pool.unregister_address, dumper=lambda x: b'{}'
        )
    with p9_server.filesystem.create('allocated') as i:
        i.metadata.call_on_read = True
        i.register_function(
            lambda: {
                address_pool.inet_ntoa(*x[0]): x[1].node
                for x in address_pool.allocated.items()
            },
            loader=lambda x: {},
        )
    with p9_server.filesystem.create('graph') as i:
        i.metadata.call_on_read = True
        i.register_function(address_pool.export_graph, loader=lambda x: {})

    p9_task = await p9_server.async_run()
    loop = asyncio.get_event_loop()
    for signal_num in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
        loop.add_signal_handler(
            signal_num, partial(handle_signal, [p9_task], signal_num)
        )
    await p9_task


def run():
    config = ConfigParser()
    config.read('config/server.ini')

    if len(sys.argv) > 1:
        config['plan9']['port'] = sys.argv[1]
    try:
        asyncio.run(main(config=config))
    except asyncio.exceptions.CancelledError:
        pass


if __name__ == '__main__':
    run()
