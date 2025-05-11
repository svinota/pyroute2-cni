import logging
from configparser import ConfigParser
from typing import Any

from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.protocols import PluginProtocol
from pyroute2_cni.request import CNIRequest


class MyPlugin(PluginProtocol):
    async def resync(
        self, address_pool: AddressPool, config: ConfigParser
    ) -> None:
        logging.debug('here we run system recovery after restart')

    async def cleanup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        config: ConfigParser,
    ) -> dict[str, Any]:
        '''Cleanup the network on a container removal.

        * data: CNI JSON that should be updated and returned.
        * request: the request object that contains CNI input,
          environment variables, and the netns file descriptor.
        * pool: the default IPAM address pool.
        * config: the ConfigMap from the kubernetes manifest.
        '''
        logging.debug('here we run cleanup on a container removal')
        return data

    async def setup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        config: ConfigParser,
    ) -> dict[str, Any]:
        '''Setup the network on a container start.

        * data: CNI JSON that should be updated and returned.
        * request: the request object that contains CNI input,
          environment variables, and the netns file descriptor.
        * pool: the default IPAM address pool.
        * config: the ConfigMap from the kubernetes manifest.

        CNI json format:
        https://github.com/containernetworking/cni/blob/main/SPEC.md

        The request data structure: `/pyroute2_cni/request.py`
        '''
        logging.debug('here we setup the network for a new container')
        return data
