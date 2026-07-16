import asyncio
import contextlib
import errno
import json
import logging
import os
import shutil
import signal
import socket
import struct
import tempfile
import time
import uuid
from configparser import ConfigParser
from functools import partial
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from pydantic import ValidationError

from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.config_defaults import (
    DEFAULT_LOG_LEVEL,
    READINESS_HOST,
    READINESS_PORT,
    config_set_defaults,
)
from pyroute2_cni.controllers.cniconfigselection_controller import (
    CNIConfigSelectionController,
)
from pyroute2_cni.controllers.namespace_controller import NamespaceController
from pyroute2_cni.controllers.vrf_controller import VRFController
from pyroute2_cni.controllers.vrnc_controller import VRFNodeConfigController
from pyroute2_cni.managers.frr_manager import FRRManager
from pyroute2_cni.network import CNIError
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest

PLUGIN_NAME = 'pyroute2-cni-plugin'


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
        # forget RID
        self.registry.pop(str(request.rid), None)
        try:
            self.cni_response(await func(data, request))
        except CNIError as e:
            logging.exception('CNI request %s failed', request.rid)
            self.cni_response(
                {
                    'cniVersion': request.cni.cniVersion,
                    'code': e.code,
                    'msg': e.msg,
                    'details': e.details,
                }
            )
        except Exception as e:
            logging.exception('CNI request %s failed', request.rid)
            self.cni_response(
                {
                    'cniVersion': request.cni.cniVersion,
                    'code': 11,
                    'msg': str(e),
                    'details': str(e),
                }
            )


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
    port: int = int(READINESS_PORT),
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


async def run_periodic_job(
    job: Callable[[], Awaitable[int]], interval: int, description: str
) -> None:
    while True:
        try:
            await asyncio.sleep(interval)
            await job()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logging.warning('%s failed: %s', description, e)


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


@contextlib.contextmanager
def temp_asset_path(dir: Path, prefix: str):
    tmp = tempfile.NamedTemporaryFile(dir=dir, prefix=prefix, delete=False)
    path = Path(tmp.name)
    try:
        tmp.close()
        yield path
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


def install_cni_assets() -> None:
    image_dir = Path('/pyroute2-cni')
    host_bin_dir = Path('/host/opt/cni/bin')
    plugin_src = image_dir / PLUGIN_NAME
    if not plugin_src.is_file():
        raise FileNotFoundError(f'Missing CNI plugin: {plugin_src}')
    host_bin_dir.mkdir(parents=True, exist_ok=True)
    plugin_dst = host_bin_dir / PLUGIN_NAME
    with temp_asset_path(host_bin_dir, f'.{PLUGIN_NAME}.') as temp_path:
        for _ in range(10):
            try:
                shutil.copy2(plugin_src, temp_path)
                os.replace(temp_path, plugin_dst)
                logging.info(f'Installed binary: {plugin_dst}')
                return
            except OSError as e:
                if e.errno != errno.ETXTBSY:
                    raise
                time.sleep(1)
        raise RuntimeError('Could not ensure the assets')


async def main(config: ConfigParser) -> None:
    registry: dict[str, CNIRequest] = {}
    ready = asyncio.Event()
    namespace_ready = asyncio.Event()
    vrf_ready = asyncio.Event()
    vrfnodeconfig_ready = asyncio.Event()

    await run_fd_receiver(
        registry, socket_path=config['api']['socket_path_fd']
    )
    readiness_server = await run_readiness_server(
        ready,
        registry,
        host=config['readiness']['host'],
        port=int(config['readiness']['port']),
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
    namespace_watch_queue: asyncio.Queue[tuple[str, str] | None] = (
        asyncio.Queue()
    )
    vrf_domain_watch_queue: asyncio.Queue[tuple[str, Any] | None] = (
        asyncio.Queue()
    )
    vrfnodeconfig_watch_queue: asyncio.Queue[tuple[str, Any] | None] = (
        asyncio.Queue()
    )
    namespace_controller = NamespaceController(config)
    frr_manager = FRRManager('/pyroute2-cni/templates/frr.conf.tpl', config)
    vrf_controller = VRFController(config, address_pool, frr_manager)
    vrfnodeconfig_controller = VRFNodeConfigController(config, frr_manager)
    cniconfigselection_controller = CNIConfigSelectionController(config)
    namespace_watch_task = asyncio.create_task(
        namespace_controller.watch(namespace_watch_queue, namespace_ready)
    )
    vrf_domain_watch_task = asyncio.create_task(
        vrf_controller.watch(vrf_domain_watch_queue, vrf_ready)
    )
    vrfnodeconfig_watch_task = asyncio.create_task(
        vrfnodeconfig_controller.watch(
            vrfnodeconfig_watch_queue, vrfnodeconfig_ready
        )
    )
    cniconfigselection_watch_queue: asyncio.Queue[tuple[str, Any] | None] = (
        asyncio.Queue()
    )
    cniconfigselection_ready = asyncio.Event()
    cniconfigselection_watch_task = asyncio.create_task(
        cniconfigselection_controller.watch(
            cniconfigselection_watch_queue, cniconfigselection_ready
        )
    )
    address_pool_gc_task = asyncio.create_task(
        run_periodic_job(
            address_pool.gc_empty_blocks,
            int(config['default']['gc_interval_seconds']),
            'periodic IPBlock gc',
        )
    )
    vrf_periodic_task = asyncio.create_task(
        run_periodic_job(
            vrf_controller.reconcile_firewall,
            int(config['default']['fw_interval_seconds']),
            'periodic VRF firewall reconciliation',
        )
    )

    await asyncio.gather(
        namespace_ready.wait(),
        vrf_ready.wait(),
        vrfnodeconfig_ready.wait(),
        cniconfigselection_ready.wait(),
    )
    cni_server = CNIServer(config, registry, plugin)
    await cni_server.setup_endpoint()

    loop = asyncio.get_event_loop()
    for signal_num in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT):
        loop.add_signal_handler(
            signal_num,
            partial(
                handle_signal,
                [
                    namespace_watch_task,
                    vrf_domain_watch_task,
                    vrfnodeconfig_watch_task,
                    cniconfigselection_watch_task,
                    address_pool_gc_task,
                    vrf_periodic_task,
                ],
                signal_num,
            ),
        )
    try:
        await asyncio.gather(
            namespace_watch_task,
            vrf_domain_watch_task,
            vrfnodeconfig_watch_task,
            cniconfigselection_watch_task,
            address_pool_gc_task,
            vrf_periodic_task,
        )
    finally:
        namespace_watch_task.cancel()
        vrf_domain_watch_task.cancel()
        vrfnodeconfig_watch_task.cancel()
        cniconfigselection_watch_task.cancel()
        address_pool_gc_task.cancel()
        vrf_periodic_task.cancel()
        readiness_server.close()
        await readiness_server.wait_closed()
        with contextlib.suppress(asyncio.CancelledError):
            await namespace_watch_task
        with contextlib.suppress(asyncio.CancelledError):
            await vrf_domain_watch_task
        with contextlib.suppress(asyncio.CancelledError):
            await vrfnodeconfig_watch_task
        with contextlib.suppress(asyncio.CancelledError):
            await cniconfigselection_watch_task
        with contextlib.suppress(asyncio.CancelledError):
            await address_pool_gc_task
        with contextlib.suppress(asyncio.CancelledError):
            await vrf_periodic_task


def run():
    config = ConfigParser()
    config.read('config/server.ini')
    config_set_defaults(config)
    logging_level = getattr(
        logging,
        config.get('logging', 'level', fallback=DEFAULT_LOG_LEVEL).upper(),
        logging.INFO,
    )
    logging.basicConfig(level=logging_level)

    install_cni_assets()
    try:
        asyncio.run(main(config=config))
    except asyncio.exceptions.CancelledError:
        pass


if __name__ == '__main__':
    run()
