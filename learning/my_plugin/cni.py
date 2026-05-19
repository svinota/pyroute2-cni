import logging
from typing import Any

from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest


class MyPlugin(PluginProtocol):
    async def resync(self) -> None:
        logging.debug('here we run system recovery after restart')

    async def cleanup(
        self, data: dict[str, Any], request: CNIRequest, p9server: Any
    ) -> dict[str, Any]:
        '''Cleanup the network on a container removal.

        * data: CNI JSON that should be updated and returned.
        * request: the request object that contains CNI input,
          environment variables, and the netns file descriptor.
        * p9server: the Plan9 filesystem server.
        '''
        logging.debug('here we run cleanup on a container removal')
        return data

    async def setup(
        self, data: dict[str, Any], request: CNIRequest, p9server: Any
    ) -> dict[str, Any]:
        '''Setup the network on a container start.

        * data: CNI JSON that should be updated and returned.
        * request: the request object that contains CNI input,
          environment variables, and the netns file descriptor.
        * p9server: the Plan9 filesystem server.

        CNI json format:
        https://github.com/containernetworking/cni/blob/main/SPEC.md

        The request data structure: `/pyroute2_cni/request.py`
        '''
        logging.debug('here we setup the network for a new container')
        return data
