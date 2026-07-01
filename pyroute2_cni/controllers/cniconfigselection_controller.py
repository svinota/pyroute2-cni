import json
import logging
import time
from configparser import ConfigParser
from pathlib import Path

from pyroute2_cni.controllers.base_crd_controller import BaseCRDWatchController
from pyroute2_cni.crds.cni_config import CNIConfig, parse_cni_config
from pyroute2_cni.crds.cni_config_selection import (
    CNIConfigSelection,
    parse_cni_config_selection,
)


class CNIConfigSelectionController(BaseCRDWatchController[CNIConfigSelection]):
    '''
    This controller should be started from the CNI daemonset pods.

    It watches CNIConfigSelection, and updates the config file on
    the host filesystem.
    '''

    plural = 'cniconfigselections'
    watch_name = 'cniconfigselection'

    def __init__(self, config: ConfigParser) -> None:
        super().__init__()
        self.config = config
        self.cni_config_dir = Path(self.config['default']['cni_config_dir'])

    def _parse_payload(
        self, obj: dict[str, object]
    ) -> CNIConfigSelection | None:
        return parse_cni_config_selection(obj)

    async def resync(self) -> None:
        logging.info('Running resync')
        response = self.custom_api.list_cluster_custom_object(
            self.group, self.version, self.plural
        )
        selections = [
            parse_cni_config_selection(item)
            for item in response.get('items', [])
        ]
        if selections:
            await self.reconcile(selections[0])

    async def reconcile(self, selection: CNIConfigSelection) -> None:
        while True:
            try:
                response = self.custom_api.list_cluster_custom_object(
                    self.group, self.version, 'cniconfigs'
                )
                configs = [
                    parse_cni_config(item)
                    for item in response.get('items', [])
                    if parse_cni_config(item).enabled
                ]
                active_name = selection.active_ref.name
                active_config = next(
                    (
                        config
                        for config in configs
                        if config.name == active_name
                    ),
                    None,
                )
                if active_config is not None:
                    self._write_config(active_config)
                for config in configs:
                    if config.name == active_name:
                        continue
                    self._remove_config(config)
                return
            except Exception as e:
                logging.error('CNIConfigSelection reconcile failed: %s', e)
                time.sleep(1)

    def _write_config(self, config: CNIConfig) -> None:
        self.cni_config_dir.mkdir(parents=True, exist_ok=True)
        path = self.cni_config_dir / self._config_filename(config)
        logging.info(f'Ensure present=true, config: {path}')
        path.write_text(self._render_config(config), encoding='utf-8')

    def _remove_config(self, config: CNIConfig) -> None:
        path = self.cni_config_dir / self._config_filename(config)
        logging.info(f'Ensure present=false, config={path}')
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def _config_filename(self, config: CNIConfig) -> str:
        return '99-pyroute2.conflist'

    def _render_config(self, config: CNIConfig) -> str:
        return json.dumps(
            {
                'name': config.name,
                'cniVersion': '0.4.0',
                'plugins': config.plugins,
            },
            indent=2,
        )

    async def ensure(self, selection: CNIConfigSelection) -> None:
        logging.info(f'CNIConfigSelection ADD/MODIFY event: {selection.name}')
        await self.reconcile(selection)

    async def remove(self, selection: CNIConfigSelection) -> None:
        logging.info(f'CNIConfigSelection DEL event: {selection.name}')
        try:
            for entry in self.cni_config_dir.iterdir():
                if entry.is_file():
                    entry.unlink()
        except FileNotFoundError:
            pass
