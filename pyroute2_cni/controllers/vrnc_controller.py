import asyncio
import logging
import threading
from configparser import ConfigParser

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import watch as k8s_watch  # type: ignore[attr-defined]

from pyroute2_cni.frr_manager import FRRManager


class VRFNodeConfigController:
    def __init__(self, config: ConfigParser, frr_manager: FRRManager) -> None:
        self.config = config
        self.frr_manager = frr_manager
        self.vrf_custom_api = k8s_client.CustomObjectsApi()

    async def reconcile(self, node_name: str, event_type: str) -> None:
        logging.info(f'VRFNodeConfig {event_type} event: {node_name}')
        await self.frr_manager.reload({})

    def _watch_worker(
        self,
        queue: asyncio.Queue[tuple[str, str] | None],
        loop: asyncio.AbstractEventLoop,
        stop_event: threading.Event,
    ) -> None:
        try:
            k8s_config.load_incluster_config()  # type: ignore[attr-defined]
        except Exception as e:
            logging.error(f'error starting vrfnodeconfig watch: {e}')
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return

        watcher = k8s_watch.Watch()
        resource_version = ''

        def refresh_resource_version() -> str:
            response = self.vrf_custom_api.list_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfnodeconfigs'
            )
            metadata = response.get('metadata') or {}
            rv = str(metadata.get('resourceVersion') or '')
            logging.info('vrfnodeconfig watch relisted at rv=%s', rv)
            return rv

        try:
            while not stop_event.is_set():
                try:
                    for event in watcher.stream(
                        self.vrf_custom_api.list_cluster_custom_object,
                        'cni.pyroute2.org',
                        'v1alpha1',
                        'vrfnodeconfigs',
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
                        name = str(metadata.get('name') or '')
                        if event_type in {'ADDED', 'MODIFIED', 'DELETED'} and name:
                            loop.call_soon_threadsafe(
                                queue.put_nowait, (event_type, name)
                            )
                except ApiException as e:
                    if e.status == 410 or 'Expired' in str(e):
                        logging.warning(
                            'vrfnodeconfig watch expired rv=%s, resetting: %s',
                            resource_version,
                            e,
                        )
                        resource_version = refresh_resource_version()
                        continue
                    logging.warning(
                        'vrfnodeconfig watch api exception, restarting rv=%s: %s',
                        resource_version,
                        e,
                    )
                except Exception as e:
                    logging.warning(
                        'vrfnodeconfig watch failed, restarting rv=%s: %s',
                        resource_version,
                        e,
                    )
        finally:
            watcher.stop()
            loop.call_soon_threadsafe(queue.put_nowait, None)

    async def watch(
        self,
        queue: asyncio.Queue[tuple[str, str] | None],
        ready: asyncio.Event,
    ) -> None:
        loop = asyncio.get_running_loop()
        stop_event = threading.Event()
        worker = threading.Thread(
            target=self._watch_worker,
            args=(queue, loop, stop_event),
            daemon=True,
        )
        worker.start()
        ready.set()
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                event_type, name = item
                await self.reconcile(name, event_type)
        finally:
            stop_event.set()
            worker.join(timeout=5)
