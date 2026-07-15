import os
from configparser import ConfigParser

from pyroute2_cni.kubernetes import get_node_ip

DEFAULT_LOG_LEVEL = 'INFO'
GC_INTERVAL_SECONDS = '300'
FW_INTERVAL_SECONDS = '30'
CNI_CONFIG_DIR = '/host/etc/cni/net.d'
READINESS_HOST = '0.0.0.0'
READINESS_PORT = '24800'


def config_set_defaults(config: ConfigParser) -> None:
    config.setdefault('api', {})
    config.setdefault('network', {})
    config.setdefault('readiness', {})
    config.setdefault('logging', {})
    config.setdefault('default', {})
    config['api'].setdefault('socket_path_api', '/var/run/pyroute2/api')
    config['api'].setdefault('socket_path_fd', '/var/run/pyroute2/fdpass')
    config['network'].setdefault('node_name', os.environ['NODE_NAME'])
    node_ip = get_node_ip(config['network']['node_name'])
    config['network'].setdefault('ipaddr', node_ip)
    config['logging'].setdefault('level', DEFAULT_LOG_LEVEL)
    config['default'].setdefault('vrf', '42')
    config['default'].setdefault('ipblocklen', '26')
    config['default'].setdefault('service_vrf_max', '512')
    config['default'].setdefault('system_vrf_type', 'l3vni')
    config['default'].setdefault('gc_interval_seconds', GC_INTERVAL_SECONDS)
    config['default'].setdefault('fw_interval_seconds', FW_INTERVAL_SECONDS)
    config['default'].setdefault('cni_config_dir', CNI_CONFIG_DIR)
    config['readiness'].setdefault('host', READINESS_HOST)
    config['readiness'].setdefault('port', READINESS_PORT)
