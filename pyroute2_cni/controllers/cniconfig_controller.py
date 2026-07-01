import logging
import time
from configparser import ConfigParser

from kubernetes.client.exceptions import ApiException

from pyroute2_cni.controllers.base_crd_controller import BaseCRDWatchController
from pyroute2_cni.crds.cni_config import (
    CNIConfig,
    default_cni_config,
    parse_cni_config,
)
from pyroute2_cni.crds.cni_config_selection import (
    CNIConfigSelection,
    CNIConfigSelectionActiveRef,
    parse_cni_config_selection,
)


class CNIConfigController(BaseCRDWatchController[CNIConfig]):
    plural = 'cniconfigs'
    watch_name = 'cniconfig'

    def __init__(self, config: ConfigParser) -> None:
        super().__init__()
        self.config = config

    def _parse_payload(self, obj: dict[str, object]) -> CNIConfig | None:
        return parse_cni_config(obj)

    async def resync(self) -> None:
        logging.info('Running resync')
        listed = await self.reconcile()
        if listed == 0:
            logging.info('Create default config')
            default = default_cni_config()
            try:
                self.custom_api.create_cluster_custom_object(
                    self.group, self.version, self.plural, default.render()
                )
            except Exception as e:
                logging.error('CNIConfig default create failed: %s', e)
            logging.info('Done')

    async def reconcile(self, exclude: list[CNIConfig] | None = None) -> int:
        exclude_names = {item.name for item in (exclude or [])}
        while True:
            try:
                response = self.custom_api.list_cluster_custom_object(
                    self.group, self.version, self.plural
                )
                items = [
                    item
                    for item in response.get('items', [])
                    if (config := parse_cni_config(item)).enabled
                    and config.name not in exclude_names
                ]
                configs = sorted(
                    (parse_cni_config(item) for item in items),
                    key=lambda item: item.priority,
                    reverse=True,
                )
                listed_count = len(configs)
                active_name = configs[0].name if configs else None
                for config in configs:
                    desired_active = config.name == active_name
                    current_active = bool(
                        config.status and config.status.active
                    )
                    if current_active == desired_active:
                        continue
                    self.custom_api.patch_namespaced_custom_object_status(
                        self.group,
                        self.version,
                        '',
                        self.plural,
                        config.name,
                        {'status': {'active': desired_active}},
                    )
                if active_name:
                    self.reconcile_selection(active_name)
                return listed_count
            except Exception as e:
                logging.error('CNIConfig reconcile failed: %s', e)
                time.sleep(1)

    def reconcile_selection(self, active_name: str) -> None:
        try:
            selection = parse_cni_config_selection(
                self.custom_api.get_cluster_custom_object(
                    self.group, self.version, 'cniconfigselections', 'default'
                )
            )
            if selection.active_ref.name == (active_name):
                return
            self.custom_api.patch_namespaced_custom_object(
                self.group,
                self.version,
                '',
                'cniconfigselections',
                'default',
                {'spec': {'activeRef': {'name': active_name}}},
            )
        except ApiException as e:
            if e.status != 404:
                raise
            self.custom_api.create_cluster_custom_object(
                self.group,
                self.version,
                'cniconfigselections',
                CNIConfigSelection(
                    name='default',
                    generation=0,
                    active_ref=CNIConfigSelectionActiveRef(name=active_name),
                    status=None,
                ).render(),
            )

    async def ensure(self, cniconfig: CNIConfig) -> None:
        logging.info(f'CNIConfig ADD/MODIFY event: {cniconfig.name}')
        await self.reconcile()

    async def remove(self, cniconfig: CNIConfig) -> None:
        logging.info(f'CNIConfig DEL event: {cniconfig.name}')
        try:
            self.custom_api.patch_namespaced_custom_object_status(
                self.group,
                self.version,
                '',
                self.plural,
                cniconfig.name,
                {'status': {'active': False}},
            )
        except Exception:
            pass
        await self.reconcile(exclude=[cniconfig])
