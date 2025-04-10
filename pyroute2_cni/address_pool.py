import asyncio
import logging
import random
import socket
import struct
import traceback

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


class AddressPool:
    def __init__(self, prefix, size, name, config):
        self.prefix = struct.pack('BB', *(int(x) for x in prefix.split('.')))
        self.size = size
        self.bits = struct.calcsize(size) * 8
        self.min = 0x1
        self.max = (1 << self.bits) - 1
        self.allocated = set()
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

    def inet_ntoa(self, addr):
        return socket.inet_ntoa(self.prefix + struct.pack('>H', addr))

    def register_address(self, address):
        self.allocated.add(address)
        return self.inet_ntoa(address)

    async def allocate(self, address=None):
        global PEERS
        if address is None:
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
                                kwarg={'address': address},
                            )
                    except Exception as e:
                        logging.error('%s' % (traceback.format_exc()))
                        logging.error(f'error: {e}')
                logging.info(f'{self.name} - {name} - {peer}')
        return self.register_address(address)

    def random(self):
        return random.randint(self.min + 1, self.max - 1)
