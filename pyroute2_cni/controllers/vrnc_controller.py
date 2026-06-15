import logging
from configparser import ConfigParser

from kubernetes import client as k8s_client
from pyroute2_cni.controllers.base_crd_controller import BaseCRDWatchController
from pyroute2_cni.frr_manager import FRRManager


class VRFNodeConfigController(BaseCRDWatchController[str]):
    plural = 'vrfnodeconfigs'
    watch_name = 'vrfnodeconfig'

    def __init__(self, config: ConfigParser, frr_manager: FRRManager) -> None:
        super().__init__()
        self.config = config
        self.frr_manager = frr_manager
        self.peer_cache: set[str] = set()

    async def reconcile(self, node_name: str, event_type: str) -> None:
        logging.info(f'VRFNodeConfig {event_type} event: {node_name}')
        current_peers = self.frr_manager.refresh_peers(k8s_client.CoreV1Api())
        peer_cleanup = self.peer_cache - current_peers
        await self.frr_manager.reload({}, peer_cleanup)
        self.peer_cache = current_peers

    async def ensure(self, node_name: str) -> None:
        await self.reconcile(node_name, 'ADD/MODIFY')

    async def remove(self, node_name: str) -> None:
        await self.reconcile(node_name, 'DEL')
