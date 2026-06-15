import asyncio
import logging
import threading
from functools import partial
from typing import Any, Generic, TypeVar

from kubernetes import client as k8s_client
from pyroute2_cni.controllers.watch_helper import run_watch_loop

T = TypeVar('T')


class BaseCRDWatchController(Generic[T]):
    group = 'cni.pyroute2.org'
    version = 'v1alpha1'
    plural = ''
    watch_name = 'crd'

    def __init__(self) -> None:
        self.custom_api = k8s_client.CustomObjectsApi()

    async def resync(self) -> None:
        return

    async def ensure(self, name: T) -> None:
        raise NotImplementedError

    async def remove(self, name: T) -> None:
        raise NotImplementedError

    def _parse_payload(self, obj: dict[str, Any]) -> T:
        metadata = obj.get('metadata') or {}
        if isinstance(metadata, dict):
            return metadata.get('name')  # type: ignore[return-value]
        raise TypeError('invalid object metadata')

    def _watch_worker(
        self,
        queue: asyncio.Queue[tuple[str, T] | None],
        loop: asyncio.AbstractEventLoop,
        stop_event: threading.Event,
    ) -> None:
        def refresh_resource_version() -> str:
            response = self.custom_api.list_cluster_custom_object(
                self.group, self.version, self.plural
            )
            metadata = response.get('metadata') or {}
            rv = str(metadata.get('resourceVersion') or '')
            logging.info(f'{self.watch_name} watch relisted at rv={rv}')
            return rv

        run_watch_loop(
            watch_name=self.watch_name,
            list_fn=partial(
                self.custom_api.list_cluster_custom_object,
                self.group,
                self.version,
                self.plural,
            ),
            event_handler=lambda event: self._handle_watch_event(event),
            queue=queue,
            loop=loop,
            stop_event=stop_event,
            refresh_resource_version=refresh_resource_version,
        )

    def _handle_watch_event(
        self, event: dict[str, Any]
    ) -> tuple[str, T] | None:
        event_type = event.get('type')
        obj = event.get('object')
        if not obj:
            return None
        if event_type not in {'ADDED', 'MODIFIED', 'DELETED'}:
            return None
        payload = self._parse_payload(obj)
        return event_type, payload

    async def watch(
        self, queue: asyncio.Queue[tuple[str, T] | None], ready: asyncio.Event
    ) -> None:
        loop = asyncio.get_running_loop()
        stop_event = threading.Event()
        worker = threading.Thread(
            target=self._watch_worker,
            args=(queue, loop, stop_event),
            daemon=True,
        )
        await self.resync()
        worker.start()
        ready.set()
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                event_type, name = item
                if event_type == 'DELETED':
                    await self.remove(name)
                else:
                    await self.ensure(name)
        finally:
            stop_event.set()
            worker.join(timeout=5)
