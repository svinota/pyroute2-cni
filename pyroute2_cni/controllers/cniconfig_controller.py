import logging
import time
from configparser import ConfigParser

from kubernetes.client.exceptions import ApiException

from pyroute2_cni.config_defaults import DEFAULT_SELECTION_NAME
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
from pyroute2_cni.crds.vrf_domain import VRFAttachment, VRFDomain


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
        created_default = False
        if listed == 0:
            logging.info('Create default config')
            created_default = self.ensure_default_config()
            logging.info('Done')

        self.ensure_default_vrf_domain()
        self.ensure_default_selection()
        if created_default:
            await self.reconcile()

    def ensure_default_selection(self) -> None:
        try:
            self.custom_api.get_cluster_custom_object(
                self.group,
                self.version,
                'cniconfigselections',
                DEFAULT_SELECTION_NAME,
            )
            return
        except ApiException as e:
            if e.status != 404:
                raise

        default = default_cni_config()
        self.ensure_default_config()
        active_name = default.name

        try:
            self.custom_api.create_cluster_custom_object(
                self.group,
                self.version,
                'cniconfigselections',
                CNIConfigSelection(
                    name=DEFAULT_SELECTION_NAME,
                    generation=0,
                    active_ref=CNIConfigSelectionActiveRef(name=active_name),
                    status=None,
                ).render(),
            )
        except ApiException as e:
            if e.status != 409:
                raise
            logging.info(
                'CNIConfigSelection %s already exists', DEFAULT_SELECTION_NAME
            )
            return
        logging.info(
            'Created default CNIConfigSelection %s -> %s',
            DEFAULT_SELECTION_NAME,
            active_name,
        )

    def ensure_default_config(self) -> bool:
        default = default_cni_config()
        try:
            self.custom_api.create_cluster_custom_object(
                self.group, self.version, self.plural, default.render()
            )
            logging.info('Created default CNIConfig name=%s', default.name)
            return True
        except ApiException as e:
            if e.status != 409:
                raise
            logging.info(
                'Default CNIConfig already exists name=%s', default.name
            )
            return False
        except Exception as e:
            logging.error('CNIConfig default create failed: %s', e)
            return False

    def ensure_default_vrf_domain(self) -> bool:
        default_vrf = int(self.config['default']['vrf'])
        default_name = f'vrf-{default_vrf}'
        try:
            self.custom_api.get_cluster_custom_object(
                self.group, self.version, 'vrfdomains', default_name
            )
            return False
        except ApiException as e:
            if e.status != 404:
                raise

        try:
            default_prefix = self.config['default']['prefix']
            default_prefixlen = int(self.config['default']['prefixlen'])
            default_ipblocklen = int(self.config['default']['ipblocklen'])
            default_vrf_type = self.config['default']['system_vrf_type']
            domain = VRFDomain(
                name=default_name,
                vrf=default_vrf,
                table=default_vrf,
                prefix=default_prefix,
                prefixlen=default_prefixlen,
                ipblocklen=default_ipblocklen,
                attachments=[
                    VRFAttachment(
                        kind=default_vrf_type, vni=default_vrf, port=4789
                    )
                ],
            )
        except (KeyError, TypeError, ValueError) as e:
            logging.error(
                (
                    'Skip default VRFDomain bootstrap: invalid [default] '
                    'config (required keys: vrf, prefix, prefixlen, '
                    'ipblocklen, system_vrf_type): %s'
                ),
                e,
            )
            return False
        try:
            self.custom_api.create_cluster_custom_object(
                self.group, self.version, 'vrfdomains', domain.render()
            )
            logging.info('Created default VRFDomain name=%s', default_name)
            return True
        except ApiException as e:
            if e.status != 409:
                raise
            logging.info(
                'Default VRFDomain already exists name=%s', default_name
            )
            return False

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
                            DEFAULT_SELECTION_NAME,
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
