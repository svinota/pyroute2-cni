import asyncio
import logging
import threading
from configparser import ConfigParser

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import watch as k8s_watch  # type: ignore[attr-defined]


class NamespaceManager:
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
        try:
            k8s_config.load_incluster_config()  # type: ignore[attr-defined]
        except Exception as e:
            logging.error(f'error starting namespace watch: {e}')
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return

        v1 = k8s_client.CoreV1Api()
        watcher = k8s_watch.Watch()
        resource_version = ''
        try:
            try:
                ns_list = v1.list_namespace()
                resource_version = (
                    getattr(ns_list.metadata, 'resource_version', None) or ''
                )
                logging.info(
                    'namespace watch starting at resource_version=%s',
                    resource_version,
                )
            except Exception as e:
                logging.warning(
                    'namespace watch initial list failed, continuing: %s', e
                )

            while not stop_event.is_set():
                try:
                    for event in watcher.stream(
                        v1.list_namespace,
                        timeout_seconds=30,
                        resource_version=resource_version or None,
                    ):
                        if stop_event.is_set():
                            break
                        event_type = event.get('type')
                        obj = event.get('object')
                        metadata = (
                            getattr(obj, 'metadata', None) if obj else None
                        )
                        rv = (
                            getattr(metadata, 'resource_version', None)
                            if metadata
                            else None
                        )
                        if rv:
                            resource_version = rv
                        logging.info(
                            'namespace watch event: type=%s name=%s rv=%s',
                            event_type,
                            getattr(metadata, 'name', None),
                            rv,
                        )
                        if event_type not in {'ADDED', 'MODIFIED', 'DELETED'}:
                            continue
                        if not obj or not metadata:
                            continue
                        loop.call_soon_threadsafe(
                            queue.put_nowait, (event_type, metadata.name)
                        )
                except ApiException as e:
                    logging.warning(
                        'namespace watch api exception, restarting rv=%s: %s',
                        resource_version,
                        e,
                    )
                except Exception as e:
                    logging.warning(
                        'namespace watch failed, restarting rv=%s: %s',
                        resource_version,
                        e,
                    )
        finally:
            watcher.stop()
            loop.call_soon_threadsafe(queue.put_nowait, None)

    async def watch(
        self, queue: asyncio.Queue[tuple[str, str] | None]
    ) -> None:
        loop = asyncio.get_running_loop()
        stop_event = threading.Event()
        worker = threading.Thread(
            target=self._watch_worker,
            args=(queue, loop, stop_event),
            daemon=True,
        )
        worker.start()
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
