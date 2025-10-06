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
from importlib.metadata import entry_points
from typing import Any, Callable, Optional

from pydantic import ValidationError
from pyroute2 import AsyncIPRoute, Plan9ServerSocket

from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest

logging.basicConfig(level=logging.DEBUG)


class CNIProtocol(asyncio.Protocol):

    transport: asyncio.Transport

    def __init__(
        self,
        on_con_lost: asyncio.Future,
        registry: dict[str, CNIRequest],
        config: ConfigParser,
        address_pool: AddressPool,
        plugin: PluginProtocol,
    ):
        self.on_con_lost = on_con_lost
        self.registry = registry
        self.pool = address_pool
        self.config = config
        self.plugin = plugin

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
                    self.cni_response_task(
                        self.plugin.setup,
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
                    self.cni_response_task(
                        self.plugin.cleanup,
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
                return self.cni_response(response)

    # do not annotate
    def connection_made(self, transport):
        self.transport = transport

    def cni_response(self, data):
        return self.transport.write(json.dumps(data).encode('utf-8'))

    async def cni_response_task(
        self,
        func: Callable,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        config: ConfigParser,
    ) -> None:
        self.cni_response(await func(data, request, pool, config))


class CNIServer:

    endpoint: asyncio.AbstractServer

    def __init__(
        self,
        config: ConfigParser,
        registry: dict[str, CNIRequest],
        address_pool: AddressPool,
        plugin: PluginProtocol,
        use_event_loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.event_loop = use_event_loop or asyncio.get_event_loop()
        self.connection_lost = self.event_loop.create_future()
        self.path = config['api']['socket_path_api']
        self.registry = registry
        self.config = config
        self.address_pool = address_pool
        self.plugin = plugin

    async def setup_endpoint(self):
        self.endpoint = await self.event_loop.create_unix_server(
            lambda: CNIProtocol(
                self.connection_lost,
                self.registry,
                self.config,
                self.address_pool,
                self.plugin,
            ),
            path=self.path,
        )


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


def load_plugin():
    for ep in entry_points(group='pyroute2.cni'):
        if ep.name == 'network':
            plugin = ep.load()
            return plugin()
    raise RuntimeError('No plugin found for the network plugin')


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

    # load system state
    plugin = load_plugin()
    await plugin.resync(address_pool, config)

    cni_server = CNIServer(config, registry, address_pool, plugin)
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
    with open('config/segment.dot', 'rb') as dot:
        config['topology']['template'] = dot.read().decode('utf-8')

    if len(sys.argv) > 1:
        config['plan9']['port'] = sys.argv[1]
    try:
        asyncio.run(main(config=config))
    except asyncio.exceptions.CancelledError:
        pass


if __name__ == '__main__':
    run()
