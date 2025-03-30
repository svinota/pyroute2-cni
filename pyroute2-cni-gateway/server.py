import asyncio
import json
import logging
import os
import random
import socket
import struct
import uuid
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, PrivateAttr, ValidationError
from pyroute2 import AsyncIPRoute, Plan9ServerSocket
from pyroute2.common import uifname
from pyroute2.nftables.expressions import genex, ipv4addr, masq
from pyroute2.nftables.main import AsyncNFTables

HOST_IF = 'enp1s0'
SOCKET_PATH_STREAM = '/var/run/pyroute2/response'
SOCKET_PATH_DGRAM = '/var/run/pyroute2/main'
PR2_BRIDGE = 'pr2-bridge'
PR2_VXLAN_IF = 'pr2-vxlan147'
PR2_VXLAN = 147
PR2_MAGIC = 'pyroute2-cni nat 0x42'
P9_PORT = 8149

logging.basicConfig(level=logging.INFO)


class AddressPool:
    def __init__(self, prefix, size, name):
        self.prefix = struct.pack('BB', *(int(x) for x in prefix.split('.')))
        self.size = size
        self.bits = struct.calcsize(size) * 8
        self.min = 0x1
        self.max = (1 << self.bits) - 1
        self.allocated = set()
        self.name = name
        self.gateway = self.inet_ntoa(self.min)

    def inet_ntoa(self, addr):
        return socket.inet_ntoa(self.prefix + struct.pack('>H', addr))

    def allocate(self):
        while True:
            addr = self.random()
            if addr not in self.allocated:
                self.allocated.add(addr)
                return self.inet_ntoa(addr)

    def random(self):
        return random.randint(self.min + 1, self.max - 1)


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
        self, on_con_lost: asyncio.Future, registry: dict[str, CNIRequest]
    ):
        self.on_con_lost = on_con_lost
        self.registry = registry
        self.pool = AddressPool('10.244', 'H', '')

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
            if request.env.get('CNI_COMMAND', None) != 'ADD':
                logging.info(
                    f'return on command {request.env.get("CNI_COMMAND", None)}'
                )
                return cni_response(self.transport, response)

            logging.info('cni ready, wait for fd')
            loop = asyncio.get_event_loop()
            loop.create_task(
                setup_container_network(
                    self.transport,
                    response,
                    self.registry[request.rid],
                    self.pool,
                )
            )

    # do not annotate
    def connection_made(self, transport):
        self.transport = transport


class CNIServer:

    endpoint: asyncio.AbstractServer

    def __init__(
        self,
        path: str,
        registry: dict[str, CNIRequest],
        use_event_loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.event_loop = use_event_loop or asyncio.get_event_loop()
        self.connection_lost = self.event_loop.create_future()
        self.path = path
        self.registry = registry

    async def setup_endpoint(self):
        self.endpoint = await self.event_loop.create_unix_server(
            lambda: CNIProtocol(self.connection_lost, self.registry),
            path=self.path,
        )


def cni_response(transport, data):
    return transport.write(json.dumps(data).encode('utf-8'))


def oif(index):
    ret = []
    ret.append(genex('meta', {'key': 5, 'dreg': 1}))
    ret.append(
        genex(
            'cmp',
            {
                'sreg': 1,
                'op': 0,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', index)]]
                },
            },
        )
    )
    return ret


async def reconcile_system_firewall(pool: AddressPool, host_link: int) -> None:
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
            if rule.get('userdata') == PR2_MAGIC:
                break
        else:
            await nft_main.rule(
                'add',
                table='nat',
                chain='POSTROUTING',
                expressions=(
                    ipv4addr(src='10.244.0.0/16'),
                    ipv4addr(dst='10.0.0.0/8', op=1),
                    ipv4addr(dst='224.0.0.0/4', op=1),
                    oif(index=host_link),
                    masq(),
                ),
                userdata=PR2_MAGIC,
            )


async def setup_container_network(
    transport: asyncio.BaseTransport,
    data: dict[str, Any],
    request: CNIRequest,
    pool: AddressPool,
) -> None:
    '''
    Run network setup in the CNI_NETNS
    '''
    await request.ready()
    logging.info(f'request {request.rid} ready')

    vp0 = uifname()

    async with AsyncIPRoute() as ipr_main:
        host_link = tuple(await ipr_main.link_lookup(ifname=HOST_IF))[0]
        if not await ipr_main.link_lookup(ifname=PR2_BRIDGE):
            await ipr_main.link(
                'add', ifname=PR2_BRIDGE, kind='bridge', state='up'
            )
        (bridge,) = await ipr_main.poll(
            ipr_main.link, 'dump', ifname=PR2_BRIDGE, timeout=5
        )
        if not len(
            [
                x
                async for x in await ipr_main.addr(
                    'dump', family=socket.AF_INET, index=bridge['index']
                )
            ]
        ):
            await ipr_main.addr(
                'add',
                index=bridge['index'],
                address=f'{pool.gateway}/{pool.bits}',
            )
        if not await ipr_main.link_lookup(ifname=PR2_VXLAN_IF):
            await ipr_main.link(
                'add',
                ifname=PR2_VXLAN_IF,
                kind='vxlan',
                state='up',
                master=bridge['index'],
                vxlan_link=host_link,
                vxlan_id=PR2_VXLAN,
                vxlan_group='239.1.1.1',
            )
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

    await reconcile_system_firewall(pool, host_link)

    address = f'{pool.allocate()}/{pool.bits}'
    async with AsyncIPRoute(netns=request.netns) as ipr:
        (eth0,) = await ipr.link('get', ifname='eth0')
        await ipr.link('set', index=eth0['index'], state='up')
        await ipr.addr('add', index=eth0['index'], address=address)
        await ipr.route('add', gateway=pool.gateway)

    data['interfaces'] = [
        {
            'name': 'eth0',
            'mac': eth0.get('address'),
            'sandbox': request.env['CNI_NETNS'],
        }
    ]
    data['ips'] = [
        {'address': address, 'interface': 0, 'gateway': pool.gateway}
    ]
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


async def run_fd_receiver(registry: dict[str, CNIRequest]) -> None:
    if os.path.exists(SOCKET_PATH_DGRAM):
        os.unlink(SOCKET_PATH_DGRAM)
    server_sock_dgram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server_sock_dgram.bind(SOCKET_PATH_DGRAM)
    server_sock_dgram.setblocking(False)
    loop = asyncio.get_running_loop()
    loop.add_reader(
        server_sock_dgram, cni_request_handler, server_sock_dgram, registry
    )


async def main() -> None:
    registry: dict[str, CNIRequest] = {}

    async with AsyncIPRoute() as ipr:
        async for route in await ipr.get_default_routes():
            service_ipaddr = route.get('prefsrc')
            break

    await run_fd_receiver(registry)
    cni_server = CNIServer(SOCKET_PATH_STREAM, registry)
    await cni_server.setup_endpoint()

    p9_server = Plan9ServerSocket(address=(service_ipaddr, P9_PORT))
    inode_registry = p9_server.filesystem.create('registry')
    inode_registry.register_function(
        lambda: registry,
        loader=lambda x: {},
        dumper=lambda x: json.dumps(
            {k: v.model_dump() for k, v in x.items()}
        ).encode('utf-8'),
    )
    p9_task = await p9_server.async_run()
    await p9_task


if __name__ == '__main__':
    asyncio.run(main())
