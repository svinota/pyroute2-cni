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
        preferred_name: str | None = None
        created_default = False
        if listed == 0:
            logging.info('Create default config')
            default = default_cni_config()
            try:
                self.custom_api.create_cluster_custom_object(
                    self.group, self.version, self.plural, default.render()
                )
                preferred_name = default.name
                created_default = True
            except Exception as e:
                logging.error('CNIConfig default create failed: %s', e)
            logging.info('Done')

        self.ensure_default_selection(preferred_name=preferred_name)
        if created_default:
            await self.reconcile()

    def ensure_default_selection(self, preferred_name: str | None = None) -> None:
        try:
            self.custom_api.get_cluster_custom_object(
                self.group, self.version, 'cniconfigselections', 'default'
            )
            return
        except ApiException as e:
            if e.status != 404:
                raise

        response = self.custom_api.list_cluster_custom_object(
            self.group, self.version, self.plural
        )
        configs = [parse_cni_config(item) for item in response.get('items', [])]
        if not configs and preferred_name is None:
            return

        names = {cfg.name for cfg in configs}
        active_name = preferred_name if preferred_name in names else None
        if active_name is None and configs:
            default_name = default_cni_config().name
            active_name = default_name if default_name in names else sorted(names)[
                0
            ]
        if active_name is None:
            return

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
        logging.info('Created default CNIConfigSelection default -> %s', active_name)

    async def reconcile(self) -> int:
        while True:
            try:
                response = self.custom_api.list_cluster_custom_object(
                    self.group, self.version, self.plural
                )
                configs = [
                    parse_cni_config(item)
                    for item in response.get('items', [])
                ]
                listed_count = len(configs)

                active_name = None
                try:
                    selection = parse_cni_config_selection(
                        self.custom_api.get_cluster_custom_object(
                            self.group,
                            self.version,
                            'cniconfigselections',
                            'default',
                        )
                    )
                    active_name = selection.active_ref.name or None
                except ApiException as e:
                    if e.status != 404:
                        raise

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
                return listed_count
            except Exception as e:
                logging.error('CNIConfig reconcile failed: %s', e)
                time.sleep(1)

    async def ensure(self, cniconfig: CNIConfig) -> None:
        logging.info(f'CNIConfig ADD/MODIFY event: {cniconfig.name}')
        await self.reconcile()

    async def remove(self, cniconfig: CNIConfig) -> None:
        logging.info(f'CNIConfig DEL event: {cniconfig.name}')
        await self.reconcile()
