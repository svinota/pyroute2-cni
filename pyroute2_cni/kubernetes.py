import logging
from typing import Any

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from pyroute2_cni.request import CNIRequest


def _load_incluster_config() -> None:
    try:
        k8s_config.load_incluster_config()  # type: ignore[attr-defined]
    except Exception:
        return


def _read_k8s_object(kind: str, name: str) -> Any:
    _load_incluster_config()
    v1 = k8s_client.CoreV1Api()
    try:
        obj: Any
        if kind == 'namespace':
            obj = v1.read_namespace(name=name)
        else:
            obj = v1.read_node(name=name)
    except Exception as e:
        logging.error(f'error R reading {kind} {name}: {e}')
        return {}
    return obj


def get_namespace(name: str) -> Any:
    return _read_k8s_object('namespace', name)


def get_node(name: str) -> Any:
    return _read_k8s_object('node', name)


def get_namespace_labels(name: str) -> dict[str, str]:
    metadata = get_namespace(name).metadata
    return metadata.labels or {}


def get_namespace_annotations(name: str) -> dict[str, str]:
    metadata = get_namespace(name).metadata
    return metadata.annotations or {}


def get_node_labels(name: str) -> dict[str, str]:
    metadata = get_node(name).metadata
    return metadata.labels or {}


def get_node_annotations(name: str) -> dict[str, str]:
    metadata = get_node(name).metadata
    return metadata.annotations or {}


def get_node_ip(name: str) -> str:
    node = get_node(name)
    addresses = getattr(node.status, 'addresses', None) or []
    for addr in addresses:
        if addr.type == 'InternalIP':
            return addr.address
    for addr in addresses:
        if addr.type == 'ExternalIP':
            return addr.address
    return ''


def get_pod_tag(request: CNIRequest, tag: str, default: str = '') -> str:
    cni_args = request.env.get('CNI_ARGS', '')
    for arg in cni_args.split(';'):
        key, value = arg.split('=')
        if key == f'K8S_POD_{tag.upper()}':
            return value
    logging.warning('got no pod namespace, return default')
    return default
