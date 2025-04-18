import asyncio
import logging
import random
import socket
import struct
import traceback
from dataclasses import dataclass
from io import BytesIO

import matplotlib.pyplot as plt
import networkx as nx
from pyroute2 import Plan9ClientSocket
from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import (
    AsyncServiceBrowser,
    AsyncServiceInfo,
    AsyncZeroconf,
)

PEERS = {}


async def mdns_service_update_callback(
    zeroconf: Zeroconf, service_type: str, name: str
) -> None:
    '''
    Query and update the service info.
    '''
    global PEERS
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000)
    logging.info(f'info {info}')
    if info:
        addresses = set((x for x in info.parsed_scoped_addresses()))
        logging.info(f"  Name: {name}")
        logging.info(f"  Addresses: {', '.join(addresses)}")
        logging.info(f"  Weight: {info.weight}, priority: {info.priority}")
        logging.info(f"  Server: {info.server}")
        PEERS[name] = [(x, info.port) for x in addresses]
        if info.properties:
            logging.info("  Properties are:")
            for key, value in info.properties.items():
                logging.info(f"    {key!r}: {value!r}")
        else:
            logging.info("  No properties")
    else:
        logging.info("  No info")


def mdns_service_update_handler(
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
    state_change: ServiceStateChange,
) -> None:
    '''
    Handle mDNS service updates.
    '''
    logging.info(f'state_change {state_change}')
    logging.info(f'service_type {service_type}')
    logging.info(f'name {name}')
    task = asyncio.ensure_future(
        mdns_service_update_callback(zeroconf, service_type, name)
    )
    logging.info(f'task {task}')


@dataclass
class AddressMetadata:
    node: str
    containerid: str


class AddressPool:
    def __init__(self, prefix, size, name, config):
        self.prefix = struct.pack('BB', *(int(x) for x in prefix.split('.')))
        self.size = size
        self.bits = struct.calcsize(size) * 8
        self.min = 0x1
        self.max = (1 << self.bits) - 1
        self.allocated = {}
        self.name = name
        self.gateway = self.inet_ntoa(self.min)
        self.config = config
        self.mdns = AsyncZeroconf()
        self.info = AsyncServiceInfo(
            self.config['mdns']['service'],
            self.name,
            addresses=[socket.inet_aton(self.config['network']['ipaddr'])],
            port=int(self.config['plan9']['port']),
            properties={'role': 'candidate'},
        )
        self.browser = AsyncServiceBrowser(
            self.mdns.zeroconf,
            [self.config['mdns']['service']],
            handlers=[mdns_service_update_handler],
        )
        asyncio.ensure_future(self.mdns.async_register_service(self.info))

    def export_graph(self):
        G = nx.Graph()
        hosts = set([x.node for x in self.allocated.values()])
        for h1 in hosts:
            for h2 in hosts:
                if h1 != h2:
                    G.add_edge(h1, h2)
        for ip, x in self.allocated.items():
            G.add_edge(self.inet_ntoa(ip), x.node)
        buf = BytesIO()
        pos = nx.spring_layout(G, seed=42)
        node_colors = [
            'skyblue' if node in hosts else 'lightgreen' for node in G.nodes
        ]
        node_sizes = [800 if node in hosts else 300 for node in G.nodes]
        plt.figure(figsize=(6, 4))
        nx.draw(
            G,
            pos,
            with_labels=True,
            node_color=node_colors,
            node_size=node_sizes,
            font_size=9,
            edge_color="gray",
        )
        plt.axis('off')

        plt.savefig(buf, format='svg', bbox_inches='tight')
        plt.close()

        image_bytes = buf.getvalue()
        buf.close()
        return image_bytes

    def inet_ntoa(self, address: int) -> str:
        return socket.inet_ntoa(self.prefix + struct.pack('>H', address))

    def register_address(
        self, address: int, node: str = '', containerid: str = ''
    ) -> str:
        self.allocated[address] = AddressMetadata(node, containerid)
        return self.inet_ntoa(address)

    async def allocate(self, containerid: str = '') -> str:
        global PEERS
        address = None
        while True:
            address = self.random()
            if address not in self.allocated:
                break
        for name, peer in PEERS.items():
            if self.name != name:
                try:
                    async with Plan9ClientSocket(address=peer[0]) as p9:
                        await p9.start_session()
                        await p9.call(
                            await p9.fid('register_address'),
                            kwarg={
                                'address': address,
                                'node': self.name,
                                'containerid': containerid,
                            },
                        )
                except Exception as e:
                    logging.error('%s' % (traceback.format_exc()))
                    logging.error(f'error: {e}')
            logging.info(f'{self.name} - {name} - {peer}')
        return self.register_address(address, self.name, containerid)

    async def release(self, containerid: str = '') -> None:
        pass

    def random(self):
        return random.randint(self.min + 1, self.max - 1)
