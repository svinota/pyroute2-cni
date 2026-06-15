import asyncio
import logging
import threading
from collections.abc import Callable
from typing import Any, TypeVar

from kubernetes.client.exceptions import ApiException

from kubernetes import config as k8s_config
from kubernetes import watch as k8s_watch  # type: ignore[attr-defined]

T = TypeVar('T')


def run_watch_loop(
    watch_name: str,
    list_fn: Callable[..., Any],
    event_handler: Callable[[dict[str, Any]], tuple[str, T] | None],
    queue: asyncio.Queue[tuple[str, T] | None],
    loop: asyncio.AbstractEventLoop,
    stop_event: threading.Event,
    initial_resource_version: str = '',
    refresh_resource_version: Callable[[], str] | None = None,
) -> None:
    try:
        k8s_config.load_incluster_config()  # type: ignore[attr-defined]
    except Exception as e:
        logging.error(f'error starting {watch_name} watch: {e}')
        loop.call_soon_threadsafe(queue.put_nowait, None)
        return

    watcher = k8s_watch.Watch()
    resource_version = initial_resource_version

    try:
        while not stop_event.is_set():
            try:
                for event in watcher.stream(
                    list_fn,
                    timeout_seconds=30,
                    resource_version=resource_version or None,
                ):
                    if stop_event.is_set():
                        break
                    item = event_handler(event)
                    if not item:
                        continue
                    event_type, payload = item
                    resource_version = _update_resource_version(
                        resource_version, event.get('object')
                    )
                    loop.call_soon_threadsafe(
                        queue.put_nowait, (event_type, payload)
                    )
            except ApiException as e:
                if e.status == 410 or 'Expired' in str(e):
                    logging.warning(
                        f'{watch_name} watch expired rv={resource_version}, '
                        f'resetting: {e}'
                    )
                    if refresh_resource_version is not None:
                        resource_version = refresh_resource_version()
                    else:
                        resource_version = ''
                    continue
                logging.warning(
                    f'{watch_name} watch api exception, restarting '
                    f'rv={resource_version}: {e}'
                )
            except Exception as e:
                logging.warning(
                    f'{watch_name} watch failed, restarting '
                    f'rv={resource_version}: {e}'
                )
    finally:
        watcher.stop()
        loop.call_soon_threadsafe(queue.put_nowait, None)


def _update_resource_version(current: str, obj: Any) -> str:
    metadata = getattr(obj, 'metadata', None)
    if metadata is None and isinstance(obj, dict):
        metadata = obj.get('metadata')
    rv = getattr(metadata, 'resource_version', None)
    if rv is None and isinstance(metadata, dict):
        rv = metadata.get('resourceVersion') or metadata.get(
            'resource_version'
        )
    return str(rv or current)
