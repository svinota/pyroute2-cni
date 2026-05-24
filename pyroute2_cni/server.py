import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
import struct
import uuid
from configparser import ConfigParser
from functools import partial
from importlib.metadata import entry_points
from typing import Any, Callable, Optional

from pydantic import ValidationError

from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.kubernetes import get_node_ip
from pyroute2_cni.namespace_controller import NamespaceController
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest
from pyroute2_cni.vrf_controller import VRFController

READINESS_HOST = '0.0.0.0'
READINESS_PORT = 24800
DEFAULT_LOG_LEVEL = 'INFO'


class CNIProtocol(asyncio.Protocol):

    transport: asyncio.Transport

    def __init__(
        self,
        on_con_lost: asyncio.Future,
        registry: dict[str, CNIRequest],
        config: ConfigParser,
        plugin: PluginProtocol,
    ):
        self.on_con_lost = on_con_lost
        self.registry = registry
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
                        self.plugin.setup, response, self.registry[request.rid]
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
        self, func: Callable, data: dict[str, Any], request: CNIRequest
    ) -> None:
        self.cni_response(await func(data, request))


class CNIServer:

    endpoint: asyncio.AbstractServer

    def __init__(
        self,
        config: ConfigParser,
        registry: dict[str, CNIRequest],
        plugin: PluginProtocol,
        use_event_loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.event_loop = use_event_loop or asyncio.get_event_loop()
        self.connection_lost = self.event_loop.create_future()
        self.path = config['api']['socket_path_api']
        self.registry = registry
        self.config = config
        self.plugin = plugin

    async def setup_endpoint(self):
        self.endpoint = await self.event_loop.create_unix_server(
            lambda: CNIProtocol(
                self.connection_lost, self.registry, self.config, self.plugin
            ),
            path=self.path,
        )


def http_response(code: int, content: str) -> bytes:
    codes = {
        200: 'OK',
        404: 'Not Found',
        405: 'Method Not Allowed',
        503: 'Service Unavailable',
    }
    body = content.encode('utf-8')
    headers = (
        f'HTTP/1.1 {code} {codes[code]}\r\n'.encode('utf-8')
        + b'Content-Type: text/plain\r\n'
        + f'Content-Length: {len(body)}\r\n'.encode('utf-8')
        + b'Connection: close\r\n\r\n'
    )
    return headers + body


def render_metrics(
    ready: asyncio.Event, registry: dict[str, CNIRequest]
) -> str:
    ready_value = 1 if ready.is_set() else 0
    registry_entries = len(registry)
    return (
        '# HELP pyroute2_cni_ready Whether the server is ready\n'
        '# TYPE pyroute2_cni_ready gauge\n'
        f'pyroute2_cni_ready {ready_value}\n'
        '# HELP pyroute2_cni_registry_entries Number of tracked CNI requests\n'
        '# TYPE pyroute2_cni_registry_entries gauge\n'
        f'pyroute2_cni_registry_entries {registry_entries}\n'
    )


async def http_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ready: asyncio.Event,
    registry: dict[str, CNIRequest],
) -> None:
    try:
        request_line = await reader.readline()
        if not request_line:
            return
        method, path, _ = (
            request_line.decode('ascii').rstrip('\r\n').split(' ')
        )
        while True:
            line = await reader.readline()
            if line in (b'\r\n', b'\n', b''):
                break
        match (method, path):
            case ('GET', '/livez'):
                response = http_response(200, 'ok\n')
            case ('GET', '/readyz') if ready.is_set():
                response = http_response(200, 'ok\n')
            case ('GET', '/readyz'):
                response = http_response(503, 'starting\n')
            case ('GET', '/metrics'):
                response = http_response(200, render_metrics(ready, registry))
            case ('GET', _):
                response = http_response(404, 'not found\n')
            case _:
                response = http_response(405, '')
        writer.write(response)
        await writer.drain()
        return
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def run_readiness_server(
    ready: asyncio.Event,
    registry: dict[str, CNIRequest],
    host: str = READINESS_HOST,
    port: int = READINESS_PORT,
) -> asyncio.AbstractServer:
    return await asyncio.start_server(
        lambda r, w: http_handler(r, w, ready, registry), host=host, port=port
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


def load_plugin(config: ConfigParser, address_pool: AddressPool):
    for ep in entry_points(group='pyroute2.cni'):
        if ep.name == 'network':
            plugin = ep.load()
            return plugin(config, address_pool)
    raise RuntimeError('No plugin found for the network plugin')


async def main(config: ConfigParser) -> None:
    registry: dict[str, CNIRequest] = {}
    ready = asyncio.Event()

    await run_fd_receiver(
        registry, socket_path=config['api']['socket_path_fd']
    )
    readiness_server = await run_readiness_server(
        ready,
        registry,
        host=config['readiness'].get('host', READINESS_HOST),
        port=config['readiness'].getint('port', fallback=READINESS_PORT),
    )
    ready.set()
    node_name = os.environ['NODE_NAME']
    address_pool = AddressPool(node_name, config)

    # load system state
    plugin = load_plugin(config, address_pool)
    plugin.on_frr_ready = ready.set
    try:
        await plugin.resync()
    except FileNotFoundError as e:
        logging.error('FRR reload socket never appeared: %s', e)
        raise SystemExit(1)
    cni_server = CNIServer(config, registry, plugin)
    await cni_server.setup_endpoint()
    namespace_watch_queue: asyncio.Queue[tuple[str, str] | None] = (
        asyncio.Queue()
    )
    vrf_domain_watch_queue: asyncio.Queue[tuple[str, Any] | None] = (
        asyncio.Queue()
    )
    namespace_controller = NamespaceController(config)
    vrf_controller = VRFController(config, address_pool)
    namespace_watch_task = asyncio.create_task(
        namespace_controller.watch(namespace_watch_queue)
    )
    vrf_domain_watch_task = asyncio.create_task(
        vrf_controller.watch(vrf_domain_watch_queue)
    )
    loop = asyncio.get_event_loop()
    for signal_num in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
        loop.add_signal_handler(
            signal_num,
            partial(
                handle_signal,
                [namespace_watch_task, vrf_domain_watch_task],
                signal_num,
            ),
        )
    try:
        await asyncio.gather(namespace_watch_task, vrf_domain_watch_task)
    finally:
        namespace_watch_task.cancel()
        vrf_domain_watch_task.cancel()
        readiness_server.close()
        await readiness_server.wait_closed()
        with contextlib.suppress(asyncio.CancelledError):
            await namespace_watch_task
        with contextlib.suppress(asyncio.CancelledError):
            await vrf_domain_watch_task


def config_set_defaults(config: ConfigParser) -> None:
    if 'topology' not in config:
        config['topology'] = {}
    with open('config/segment.dot', 'rb') as dot:
        config['topology']['template'] = dot.read().decode('utf-8')
    if 'network' not in config:
        config['network'] = {}
    if 'readiness' not in config:
        config['readiness'] = {}
    if 'logging' not in config:
        config['logging'] = {}
    if 'default' not in config:
        config['default'] = {}
    config['network']['node_name'] = os.environ['NODE_NAME']
    node_ip = get_node_ip(config['network']['node_name'])
    config['network']['ipaddr'] = node_ip
    config['readiness'].setdefault('host', READINESS_HOST)
    config['readiness'].setdefault('port', str(READINESS_PORT))
    config['logging'].setdefault('level', DEFAULT_LOG_LEVEL)
    config['default'].setdefault('l3vni', "0")
    config['default'].setdefault('l2vni', "42")
    config['default'].setdefault('vrf', "42")


def run():
    config = ConfigParser()
    config.read('config/server.ini')
    config_set_defaults(config)
    logging.basicConfig(
        level=getattr(
            logging,
            config.get('logging', 'level', fallback=DEFAULT_LOG_LEVEL).upper(),
            logging.INFO,
        )
    )
    try:
        asyncio.run(main(config=config))
    except asyncio.exceptions.CancelledError:
        pass


if __name__ == '__main__':
    run()
