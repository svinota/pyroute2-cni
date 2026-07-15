import logging
from configparser import ConfigParser
from datetime import datetime, timezone
from enum import StrEnum

from kubernetes import client as k8s_client
from pyroute2_cni.controllers.base_crd_controller import BaseCRDWatchController
from pyroute2_cni.crds.vrf_node_config import (
    VRFNodeConfig,
    VRFNodeConfigCondition,
    parse_vrf_node_config,
    render_vrf_node_config_conditions,
)
from pyroute2_cni.managers.frr_manager import FRRManager


class VRFNodeConfigEventType(StrEnum):
    MODIFY = 'ADD/MODIFY'
    DEL = 'DEL'


class VRFNodeConfigController(BaseCRDWatchController[VRFNodeConfig]):
    plural = 'vrfnodeconfigs'
    watch_name = 'vrfnodeconfig'

    def __init__(self, config: ConfigParser, frr_manager: FRRManager) -> None:
        super().__init__()
        self.config = config
        self.frr_manager = frr_manager
        self.node_name = self.config['network']['node_name']
        if not self.node_name:
            raise RuntimeError('node name is not set')

    def _parse_payload(self, obj: dict[str, object]) -> VRFNodeConfig | None:
        node_config = parse_vrf_node_config(obj)
        if node_config.node_ref.name != self.node_name:
            return None
        return node_config

    def _set_conditions(
        self,
        node_config: VRFNodeConfig,
        ready: bool,
        event_type: VRFNodeConfigEventType = VRFNodeConfigEventType.MODIFY,
    ) -> None:
        if event_type == VRFNodeConfigEventType.DEL:
            return
        timestamp = datetime.now(timezone.utc)
        conditions = [
            VRFNodeConfigCondition(
                type='Accepted',
                status='True',
                observed_generation=node_config.generation,
                reason='Reconciled',
                message='VRFNodeConfig reconciled successfully',
                last_transition_time=timestamp,
            ),
            VRFNodeConfigCondition(
                type='Ready',
                status='True' if ready else 'False',
                observed_generation=node_config.generation,
                reason='Ready' if ready else 'Reconciling',
                message=(
                    'VRFNodeConfig is ready'
                    if ready
                    else 'VRFNodeConfig is reconciling'
                ),
                last_transition_time=timestamp,
            ),
        ]
        status = {
            'accepted': True,
            'ready': ready,
            'routeReflectorsCount': len(node_config.route_reflectors),
            'interfacesCount': len(node_config.interfaces),
            'conditions': render_vrf_node_config_conditions(conditions),
        }
        self.custom_api.patch_namespaced_custom_object_status(
            self.group,
            self.version,
            '',
            self.plural,
            node_config.name,
            {'status': status},
        )

    async def reconcile(
        self, node_config: VRFNodeConfig, event_type: VRFNodeConfigEventType
    ) -> None:
        node_name = node_config.name
        logging.info(f'VRFNodeConfig {event_type.value} event: {node_name}')
        self._set_conditions(node_config, False, event_type)
        current_peers = self.frr_manager.refresh_peers(k8s_client.CoreV1Api())
        peer_cleanup = self.frr_manager.peer_cache - current_peers
        await self.frr_manager.reload({}, peer_cleanup)
        self.frr_manager.peer_cache = current_peers
        self._set_conditions(node_config, True, event_type)

    async def ensure(self, node_config: VRFNodeConfig) -> None:
        try:
            await self.reconcile(node_config, VRFNodeConfigEventType.MODIFY)
        except Exception as e:
            logging.error(f'VRFNodeConfig error: {e}')
            self._set_conditions(node_config, False)
            raise

    async def remove(self, node_config: VRFNodeConfig) -> None:
        await self.reconcile(node_config, VRFNodeConfigEventType.DEL)
