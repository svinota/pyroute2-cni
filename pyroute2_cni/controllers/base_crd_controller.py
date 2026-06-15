import asyncio
import logging
import threading
from typing import Any, Generic, TypeVar

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import watch as k8s_watch  # type: ignore[attr-defined]

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
        try:
            k8s_config.load_incluster_config()  # type: ignore[attr-defined]
        except Exception as e:
            logging.error(f'error starting {self.watch_name} watch: {e}')
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return

        watcher = k8s_watch.Watch()
        resource_version = ''

        def refresh_resource_version() -> str:
            response = self.custom_api.list_cluster_custom_object(
                self.group, self.version, self.plural
            )
            metadata = response.get('metadata') or {}
            rv = str(metadata.get('resourceVersion') or '')
            logging.info(f'{self.watch_name} watch relisted at rv={rv}')
            return rv

        try:
            while not stop_event.is_set():
                try:
                    for event in watcher.stream(
                        self.custom_api.list_cluster_custom_object,
                        self.group,
                        self.version,
                        self.plural,
                        timeout_seconds=30,
                        resource_version=resource_version or None,
                    ):
                        if stop_event.is_set():
                            break
                        event_type = event.get('type')
                        obj = event.get('object')
                        if not obj:
                            continue
                        metadata = obj.get('metadata') or {}
                        rv = str(metadata.get('resourceVersion') or '')
                        if rv:
                            resource_version = rv
                        if event_type in {'ADDED', 'MODIFIED', 'DELETED'}:
                            payload = self._parse_payload(obj)
                            loop.call_soon_threadsafe(
                                queue.put_nowait, (event_type, payload)
                            )
                except ApiException as e:
                    if e.status == 410 or 'Expired' in str(e):
                        logging.warning(
                            f'{self.watch_name} watch expired '
                            f'rv={resource_version}, resetting: {e}'
                        )
                        resource_version = refresh_resource_version()
                        continue
                    logging.warning(
                        f'{self.watch_name} watch api exception, '
                        f'restarting rv={resource_version}: {e}'
                    )
                except Exception as e:
                    logging.warning(
                        f'{self.watch_name} watch failed, '
                        f'restarting rv={resource_version}: {e}'
                    )
        finally:
            watcher.stop()
            loop.call_soon_threadsafe(queue.put_nowait, None)

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
