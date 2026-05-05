import logging
import random
import struct
import traceback
from configparser import ConfigParser
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network

from pyroute2 import Plan9ClientSocket


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
