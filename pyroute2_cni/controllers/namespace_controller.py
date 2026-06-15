import asyncio
import logging
import threading
from configparser import ConfigParser

from kubernetes import client as k8s_client
from pyroute2_cni.controllers.watch_helper import run_watch_loop


class NamespaceController:
    def __init__(self, config: ConfigParser) -> None:
        self.config = config

    async def cleanup(self, namespace: str) -> None:
        logging.info(f'namespace DEL event: {namespace}')

    async def ensure(self, namespace: str) -> None:
        logging.info(f'namespace ADD/MODIFY event: {namespace}')

    def _watch_worker(
        self,
        queue: asyncio.Queue[tuple[str, str] | None],
        loop: asyncio.AbstractEventLoop,
        stop_event: threading.Event,
    ) -> None:
        v1 = k8s_client.CoreV1Api()

        def refresh_resource_version() -> str:
            ns_list = v1.list_namespace()
            rv = getattr(ns_list.metadata, 'resource_version', None) or ''
            logging.info('namespace watch relisted at rv=%s', rv)
            return rv

        run_watch_loop(
            watch_name='namespace',
            list_fn=v1.list_namespace,
            event_handler=lambda event: self._handle_watch_event(event),
            queue=queue,
            loop=loop,
            stop_event=stop_event,
            refresh_resource_version=refresh_resource_version,
        )

    def _handle_watch_event(
        self, event: dict[str, object]
    ) -> tuple[str, str] | None:
        event_type = event.get('type')
        obj = event.get('object')
        metadata = getattr(obj, 'metadata', None) if obj else None
        rv = getattr(metadata, 'resource_version', None) if metadata else None
        if event_type not in {'ADDED', 'MODIFIED', 'DELETED'}:
            return None
        if not obj or not metadata:
            return None
        logging.info(
            'namespace watch event: type=%s name=%s rv=%s',
            event_type,
            getattr(metadata, 'name', None),
            rv,
        )
        return event_type, metadata.name

    async def watch(
        self,
        queue: asyncio.Queue[tuple[str, str] | None],
        ready: asyncio.Event | None = None,
    ) -> None:
        loop = asyncio.get_running_loop()
        stop_event = threading.Event()
        worker = threading.Thread(
            target=self._watch_worker,
            args=(queue, loop, stop_event),
            daemon=True,
        )
        worker.start()
        if ready is not None:
            ready.set()
        try:
            while True:
                namespace = await queue.get()
                if namespace is None:
                    break
                event_type, name = namespace
                if event_type == 'DELETED':
                    await self.cleanup(name)
                else:
                    await self.ensure(name)
        finally:
            stop_event.set()
            worker.join(timeout=5)
