import asyncio
import logging
import random
import socket
import struct
import traceback
from configparser import ConfigParser
from dataclasses import dataclass
from functools import partial
from io import BytesIO, StringIO
from ipaddress import IPv4Address, IPv4Network

import matplotlib.pyplot as plt
import networkx as nx
from pyroute2 import Plan9ClientSocket
from zeroconf import ServiceStateChange, Zeroconf
from zeroconf.asyncio import (
    AsyncServiceBrowser,
    AsyncServiceInfo,
    AsyncZeroconf,
)


@dataclass
class AddressMetadata:
    node: str
    pod_uid: str
    is_gateway: bool
    network: str
    address: str


class AddressPool:
    def __init__(self, name: str, config: ConfigParser) -> None:
        self.allocated: dict[tuple[str, int], AddressMetadata] = {}
        self.peers: dict[str, list[tuple[str, int]]] = {}
        self.name = name
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
            handlers=[partial(mdns_service_update_handler, address_pool=self)],
        )
        asyncio.ensure_future(self.mdns.async_register_service(self.info))

    def export_graph(self) -> tuple[tuple[str, ...], nx.Graph]:
        G = nx.Graph()

        hosts = {
            y: (y, {'color': '#b2ceff'})
            for y in set([x.node for x in self.allocated.values()])
        }
        G.add_nodes_from(hosts.values())
        for h1 in hosts.keys():
            for h2 in hosts.keys():
                if h1 != h2:
                    G.add_edge(h1, h2)

        gateways = {
            (x.network, x.node): x
            for x in self.allocated.values()
            if x.is_gateway
        }
        for gateway in gateways.values():
            G.add_node(gateway.address, color='#b2ffe3')
            G.add_edge(gateway.address, gateway.node)

        containers = {
            x.address: x for x in self.allocated.values() if not x.is_gateway
        }
        for container in containers.values():
            G.add_node(container.address, color='#88ff97')
            G.add_edge(
                container.address,
                gateways.get(
                    (container.network, container.node),
                    AddressMetadata('', '', False, '', 'err'),
                ).address,
            )
        return tuple(hosts.keys()), G

    def export_graph_dot(self) -> bytes:
        _, G = self.export_graph()
        buf = StringIO()
        nx.nx_pydot.write_dot(G, buf)
        image_bytes = buf.getvalue().encode('utf-8')
        buf.close()
        return image_bytes

    def export_graph_svg(self) -> bytes:
        hosts, G = self.export_graph()
        buf = BytesIO()
        pos = nx.spring_layout(G, seed=42)
        node_sizes = [800 if node in hosts else 300 for node in G.nodes]
        plt.figure(figsize=(12, 8))
        nx.draw(
            G,
            pos,
            with_labels=True,
            node_color=[x[1].get('color', 'red') for x in G.nodes(data=True)],
            node_size=node_sizes,
            font_size=14,
            edge_color="gray",
        )
        plt.axis('off')
        plt.savefig(buf, format='svg', bbox_inches='tight')
        plt.close()
        image_bytes = buf.getvalue()
        buf.close()
        return image_bytes

    def inet_aton(self, network: IPv4Network, address: str) -> int:
        return (
            struct.unpack('>I', IPv4Address(address).packed)[0]
            & struct.unpack('>I', network.hostmask.packed)[0]
        )

    def inet_ntoa(self, network: str, address: int) -> str:
        return IPv4Network(network)[address].compressed

    def unregister_address(self, pod_uid: str) -> AddressMetadata:
        logging.info(f'pod_uid: {pod_uid}')
        address = None
        for address, metadata in tuple(self.allocated.items()):
            logging.info(f'L address {address}, pod_uid: {metadata.pod_uid}')
            logging.info(f'L {metadata.pod_uid == pod_uid}')
            logging.info(f'L {type(metadata.pod_uid)} -- {type(pod_uid)}')
            if metadata.pod_uid == pod_uid:
                break
        else:
            raise KeyError('address not allocated')
        return self.allocated.pop(address)

    async def release(self, pod_uid: str) -> AddressMetadata:
        metadata = self.unregister_address(pod_uid)
        for name, peer in self.peers.items():
            if self.name != name:
                try:
                    async with Plan9ClientSocket(address=peer[0]) as p9:
                        await p9.start_session()
                        await p9.call(
                            await p9.fid('unregister_address'),
                            kwarg={'pod_uid': pod_uid},
                        )
                except Exception as e:
                    logging.error('%s' % (traceback.format_exc()))
                    logging.error(f'error: {e}')
            logging.info(f'U {self.name} - {name} - {peer}')
        return metadata

    def register_address(
        self,
        network: str,
        address: int,
        node: str = '',
        is_gateway: bool = False,
        pod_uid: str = '',
    ) -> str:
        ret = self.inet_ntoa(network, address)
        self.allocated[(network, address)] = AddressMetadata(
            node, pod_uid, is_gateway, network, ret
        )
        return ret

    async def allocate(
        self,
        network: IPv4Network,
        is_gateway: bool = False,
        pod_uid: str = '',
        address: int = -1,
    ) -> str:
        while address < 0:
            candidate = self.random(network)
            if (network.compressed, candidate) not in self.allocated:
                address = candidate
        for name, peer in self.peers.items():
            if self.name != name:
                try:
                    async with Plan9ClientSocket(address=peer[0]) as p9:
                        await p9.start_session()
                        await p9.call(
                            await p9.fid('register_address'),
                            kwarg={
                                'network': network.compressed,
                                'address': address,
                                'node': self.name,
                                'is_gateway': is_gateway,
                                'pod_uid': pod_uid,
                            },
                        )
                except Exception as e:
                    logging.error('%s' % (traceback.format_exc()))
                    logging.error(f'error: {e}')
            logging.info(f'R {self.name} - {name} - {peer}')
        return self.register_address(
            network.compressed, address, self.name, is_gateway, pod_uid
        )

    def random(self, network: IPv4Network) -> int:
        (first_address,) = struct.unpack('>I', network[0].packed)
        (last_address,) = struct.unpack('>I', network[-1].packed)
        (hostmask,) = struct.unpack('>I', network.hostmask.packed)
        first_host = first_address & hostmask
        last_host = last_address & hostmask
        return random.randint(first_host + 1, last_host - 1)


async def mdns_service_update_task(
    address_pool: AddressPool,
    zeroconf: Zeroconf,
    service_type: str,
    name: str,
    state_change: ServiceStateChange,
) -> None:
    '''
    Query and update the service info.
    '''
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000)
    logging.info(f'info {info}')
    if info:
        addresses = set((x for x in info.parsed_scoped_addresses()))
        logging.info(f"  Name: {name}")
        logging.info(f"  Addresses: {', '.join(addresses)}")
        logging.info(f"  Weight: {info.weight}, priority: {info.priority}")
        logging.info(f"  Server: {info.server}")
        peer_addr = [(x, info.port) for x in addresses]
        address_pool.peers[name] = peer_addr
        if state_change == ServiceStateChange.Added:
            async with Plan9ClientSocket(address=peer_addr[0]) as p9:
                await p9.start_session()
                for (network, address), meta in tuple(
                    address_pool.allocated.items()
                ):
                    await p9.call(
                        await p9.fid('register_address'),
                        kwarg={
                            'network': network,
                            'address': address,
                            'node': meta.node,
                            'is_gateway': meta.is_gateway,
                            'pod_uid': meta.pod_uid,
                        },
                    )

        if info.properties:
            logging.info("  Properties are:")
            for key, value in info.properties.items():
                logging.info(f"    {key!r}: {value!r}")
        else:
            logging.info("  No properties")
    else:
        logging.info("  No info")


def mdns_service_update_handler(
    address_pool: AddressPool,
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
    task = asyncio.create_task(
        mdns_service_update_task(
            address_pool, zeroconf, service_type, name, state_change
        )
    )
    logging.info(f'task {task}')
