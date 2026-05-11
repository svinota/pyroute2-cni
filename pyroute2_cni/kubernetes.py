import logging

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from pyroute2_cni.request import CNIRequest


def get_namespace_labels(name: str) -> dict[str, str]:
    try:
        k8s_config.load_incluster_config()
    except Exception as e:
        logging.error(f'error C reading namespace {name}: {e}')
        return {}
    v1 = k8s_client.CoreV1Api()
    try:
        ns = v1.read_namespace(name=name)
    except Exception as e:
        logging.error(f'error R reading namespace {name}: {e}')
        return {}
    # except kubernetes.client.exceptions.ApiException:
    #    return {}
    return ns.metadata.labels or {}


def get_pod_tag(request: CNIRequest, tag: str, default: str = '') -> str:
    cni_args = request.env.get('CNI_ARGS', '')
    for arg in cni_args.split(';'):
        key, value = arg.split('=')
        if key == f'K8S_POD_{tag.upper()}':
            return value
    logging.warning('got no pod namespace, return default')
    return default
