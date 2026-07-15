import asyncio
import logging
from configparser import ConfigParser
from typing import Any

from pyroute2_cni.config_defaults import DEFAULT_LOG_LEVEL, config_set_defaults
from pyroute2_cni.controllers.cniconfig_controller import CNIConfigController


async def main(config: ConfigParser) -> None:
    controller = CNIConfigController(config)
    watch_queue: asyncio.Queue[tuple[str, Any] | None] = asyncio.Queue()
    ready = asyncio.Event()
    watch_task = asyncio.create_task(controller.watch(watch_queue, ready))
    try:
        await ready.wait()
        await watch_task
    finally:
        watch_task.cancel()


def run() -> None:
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
