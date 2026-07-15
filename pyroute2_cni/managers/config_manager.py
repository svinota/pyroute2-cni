import contextlib
import errno
import logging
import os
import shutil
import tempfile
import time
from pathlib import Path

CONFLIST_NAME = '05-chain.conflist'
PLUGIN_NAME = 'pyroute2-cni-plugin'


@contextlib.contextmanager
def temp_asset_path(dir: Path, prefix: str):
    tmp = tempfile.NamedTemporaryFile(dir=dir, prefix=prefix, delete=False)
    path = Path(tmp.name)
    try:
        tmp.close()
        yield path
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()


class ConfigManager:

    def install_cni_assets(self) -> None:
        image_dir = Path('/pyroute2-cni')
        host_etc_dir = Path('/host/etc/cni/net.d')
        host_bin_dir = Path('/host/opt/cni/bin')
        conflist_src = image_dir / CONFLIST_NAME
        conflist_dst = host_etc_dir / CONFLIST_NAME
        plugin_src = image_dir / PLUGIN_NAME
        if not conflist_src.is_file():
            raise FileNotFoundError(f'Missing CNI conflist: {conflist_src}')
        if not plugin_src.is_file():
            raise FileNotFoundError(f'Missing CNI plugin: {plugin_src}')
        host_etc_dir.mkdir(parents=True, exist_ok=True)
        host_bin_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(conflist_src, conflist_dst)
        logging.info(f'Installed conflist: {conflist_dst}')
        plugin_dst = host_bin_dir / PLUGIN_NAME
        with temp_asset_path(host_bin_dir, f'.{PLUGIN_NAME}.') as temp_path:
            for _ in range(10):
                try:
                    shutil.copy2(plugin_src, temp_path)
                    os.replace(temp_path, plugin_dst)
                    logging.info(f'Installed binary: {plugin_dst}')
                    return
                except OSError as e:
                    if e.errno != errno.ETXTBSY:
                        raise
                    time.sleep(1)
            raise RuntimeError('Could not ensure the assets')
