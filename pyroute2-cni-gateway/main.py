import asyncio
import socket
import os
import sys
from typing import cast
import struct
import logging
import json
import random
from functools import partial
from pyroute2.common import uifname
from pyroute2 import AsyncIPRoute
from pyroute2 import Plan9ServerSocket
from zeroconf import IPVersion, Zeroconf, ServiceStateChange
from zeroconf.asyncio import (
    AsyncZeroconf,
    AsyncServiceInfo,
    AsyncServiceBrowser
)


logging.basicConfig(level=logging.DEBUG)

P9_PORT = 8149
if len(sys.argv) > 1:
    P9_PORT = int(sys.argv[1])

HOST_IF = 'enp7s0'
PR2_BRIDGE = 'pr2-bridge'
PR2_VXLAN_IF = 'pr2-vxlan147'
PR2_VXLAN = 147
SOCKET_PATH_DGRAM = '/var/run/pyroute2/main'
SOCKET_PATH_STREAM = '/var/run/pyroute2/response'
SERVICE_TYPE = '_9p2r._tcp.local.'
PEERS = {}

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
        global PEERS
        while True:
            addr = self.random()
            if addr not in self.allocated:
                self.allocated.add(addr)
                for peer in PEERS:
                    if self.name == peer:
                        continue
                    print(" peer ", peer)
                    print(" >>>> ", PEERS[peer])
                return self.inet_ntoa(addr)

    def random(self):
        return random.randint(self.min + 1, self.max - 1)


def p9_get_allocated(pool):
    return [pool.inet_ntoa(x) for x in pool.allocated]


def p9_allocate(pool):
    return {'address': pool.allocate() }


def p9_merge(pool, addresses):
    pool.allocated.update(set(addresses))
    return p9_get_allocated(pool)


async def mdns_service_update_callback(
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
) -> None:
    '''
    Query and update the service info.
    '''
    global PEERS
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000)
    print('info', info)
    if info:
        addresses = set((x for x in info.parsed_scoped_addresses()))
        print(f"  Name: {name}")
        print(f"  Addresses: {', '.join(addresses)}")
        print(f"  Weight: {info.weight}, priority: {info.priority}")
        print(f"  Server: {info.server}")
        PEERS[name] = [ (x, info.port) for x in addresses ]
        if info.properties:
            print("  Properties are:")
            for key, value in info.properties.items():
                print(f"    {key!r}: {value!r}")
        else:
            print("  No properties")
    else:
        print("  No info")
    print("\n")


def mdns_service_update_handler(
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
    state_change: ServiceStateChange
) -> None:
    '''
    Handle mDNS service updates.
    '''
    print('state_change', state_change)
    print('service_type', service_type)
    print('name', name)
    task = asyncio.ensure_future(
        mdns_service_update_callback(
            zeroconf,
            service_type,
            name
        )
    )
    print(task)


def cni_response(sock_stream, data):
    client, _ = sock_stream.accept()
    print(" R ", json.dumps(data).encode('utf-8'))
    client.send(json.dumps(data).encode('utf-8'))


async def setup_container_network(fd, req, sock_stream, pool):
    '''
    Run network setup in the CNI_NETNS
    '''
    if not isinstance(req['cni'], dict):
        return cni_response(
            sock_stream,
            {'cniVersion': req['cni']['cniVersion']}
        )

    # data = req['cni']['prevResult']
    data = {
        'cniVersion': req['cni']['cniVersion'],
    }
    if req['env'].get('CNI_COMMAND', None) != 'ADD':
        return cni_response(sock_stream, data)

    vp0 = uifname()

    async with AsyncIPRoute() as ipr_main:
        if not await ipr_main.link_lookup(ifname=PR2_BRIDGE):
            await ipr_main.link(
                'add',
                ifname=PR2_BRIDGE,
                kind='bridge',
                state='up',
            )
        bridge, = await ipr_main.poll(
            ipr_main.link, 'dump', ifname=PR2_BRIDGE, timeout=5
        )
        if not len([x async for x in await ipr_main.addr(
            'dump',
            family=socket.AF_INET,
            index=bridge['index'],
        )]):
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
                vxlan_link=await ipr_main.link_lookup(ifname=HOST_IF),
                vxlan_id=PR2_VXLAN,
                vxlan_group='239.1.1.1',
            )
        await ipr_main.link(
            'add',
            kind='veth',
            ifname=vp0,
            state='up',
            peer={
                'ifname': 'eth0',
                'net_ns_fd': fd,
            },
        )
        port, = await ipr_main.poll(
            ipr_main.link,
            'dump',
            ifname=vp0,
            timeout=5
        )
        await ipr_main.link('set', index=port['index'], master=bridge['index'])

    address = f'{pool.allocate()}/{pool.bits}'
    async with AsyncIPRoute(netns=fd) as ipr:
        eth0, = await ipr.link('get', ifname='eth0')
        await ipr.link('set', index=eth0['index'], state='up')
        await ipr.addr(
            'add',
            index=eth0['index'],
            address=address,
        )
        await ipr.route(
            'add',
            gateway=pool.gateway,
        )

    data['interfaces'] = [
        {
            'name': 'eth0',
            'mac': eth0.get('address'),
            'sandbox': req['env']['CNI_NETNS'],
        },
    ]
    data['ips'] = [
        {
            'address': address,
            'interface': 0,
            'gateway': pool.gateway,
        },
    ]
    data['routes'] = [
        {
            'dst': '0.0.0.0/0',
        },
    ]
    os.close(fd)
    logging.info(f'>>> {data}')
    return cni_response(sock_stream, data)


def cni_request_handler(sock_dgram, sock_stream, pool):
    '''
    Receive JSON CNI config and CNI_NETNS file descriptor.
    '''
    msg, ancdata, _, _ = sock_dgram.recvmsg(4096, socket.CMSG_SPACE(4))
    req = json.loads(msg.decode('utf-8'))
    if ancdata:
        cmsg_level, cmsg_type, packed_fd = ancdata[0]
        if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
            received_fd = struct.unpack("i", packed_fd)[0]
            print(f"--> {received_fd}")
            loop = asyncio.get_running_loop()
            loop.create_task(
                setup_container_network(
                    received_fd,
                    req,
                    sock_stream,
                    pool,
                )
            )


async def run_cni_interface(pool):
    '''
    Launch CNI server interface to accept the plugin's requests.
    '''

    if os.path.exists(SOCKET_PATH_DGRAM):
        os.unlink(SOCKET_PATH_DGRAM)
    if os.path.exists(SOCKET_PATH_STREAM):
        os.unlink(SOCKET_PATH_STREAM)

    server_sock_dgram = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server_sock_dgram.bind(SOCKET_PATH_DGRAM)
    server_sock_dgram.setblocking(False)

    server_sock_stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server_sock_stream.bind(SOCKET_PATH_STREAM)
    server_sock_stream.listen(1)

    loop = asyncio.get_running_loop()
    loop.add_reader(
        server_sock_dgram,
        cni_request_handler,
        server_sock_dgram,
        server_sock_stream,
        pool,
    )

async def main():
    global SERVICE_TYPE

    name = f'pyroute2-cni-gateway-{uifname()}.{SERVICE_TYPE}'
    print(f'starting {name}')

    # look for the address to use
    async with AsyncIPRoute() as ipr:
        async for route in await ipr.get_default_routes():
            service_ipaddr = route.get('prefsrc')

    mdns = AsyncZeroconf()
    info = AsyncServiceInfo(
        SERVICE_TYPE,
        name,
        addresses=[socket.inet_aton(service_ipaddr)],
        port=P9_PORT,
        properties={'role': 'candidate'},
    )
    await mdns.async_register_service(info)
    browser = AsyncServiceBrowser(
        mdns.zeroconf,
        [SERVICE_TYPE],
        handlers=[mdns_service_update_handler],
    )
    pool = AddressPool('10.244', 'H', name)
    server = Plan9ServerSocket(address=(service_ipaddr, P9_PORT))
    inode_get_allocated = server.filesystem.create('get_allocated')
    inode_allocate = server.filesystem.create('allocate')

    inode_get_allocated.register_function(
        partial(
            p9_get_allocated,
            pool,
        ),
        loader=lambda x: {},
        dumper=lambda x: json.dumps(x).encode('utf-8'),
    )
    inode_allocate.register_function(
        partial(
            p9_allocate,
            pool,
        ),
        loader=lambda x: {},
        dumper=lambda x: json.dumps(x).encode('utf-8'),
    )
    await server.async_run()

    await run_cni_interface(pool)
    await asyncio.sleep(600)


asyncio.run(main())
