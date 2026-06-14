import pytest

from kubernetes import client, config

from .data import NamespaceEnv, PodInfo, PodsEnv
from .utils import (
    get_ip,
    get_mac,
    namespace_gone,
    pod_gone,
    pod_running,
    unique_name,
    wait_for,
)


@pytest.fixture
def env_namespace():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    namespace = NamespaceEnv(v1, unique_name('test-ns'))
    try:
        v1.create_namespace(namespace.manifest)
        yield namespace
    finally:
        v1.delete_namespace(name=namespace.name)
        wait_for(lambda: namespace_gone(v1, namespace.name))


@pytest.fixture
def env_pods(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    pod_1 = PodInfo(unique_name('pod'))
    pod_2 = PodInfo(unique_name('pod'))
    try:
        v1.create_namespaced_pod(namespace=namespace, body=pod_1.manifest)
        v1.create_namespaced_pod(namespace=namespace, body=pod_2.manifest)
        wait_for(lambda: pod_running(v1, pod_1.name, namespace))
        wait_for(lambda: pod_running(v1, pod_2.name, namespace))
        wait_for(lambda: get_ip(v1, pod_1.name, namespace) is not None)
        wait_for(lambda: get_ip(v1, pod_2.name, namespace) is not None)
        ip_1 = get_ip(v1, pod_1.name, namespace)
        ip_2 = get_ip(v1, pod_2.name, namespace)
        mac_1 = get_mac(v1, pod_1.name, namespace)
        mac_2 = get_mac(v1, pod_2.name, namespace)
        object.__setattr__(pod_1, 'ip', ip_1)
        object.__setattr__(pod_2, 'ip', ip_2)
        object.__setattr__(pod_1, 'mac', mac_1)
        object.__setattr__(pod_2, 'mac', mac_2)
        yield PodsEnv(v1, namespace, [pod_1, pod_2])
    finally:
        v1.delete_namespaced_pod(name=pod_1.name, namespace=namespace)
        v1.delete_namespaced_pod(name=pod_2.name, namespace=namespace)
        wait_for(lambda: pod_gone(v1, namespace, pod_1.name))
        wait_for(lambda: pod_gone(v1, namespace, pod_2.name))
