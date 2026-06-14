import time

import pytest

from .data import PodInfo
from .utils import (
    get_ip,
    packets_received,
    pod_gone,
    pod_running,
    run_cmd,
    unique_name,
    wait_for,
)


@pytest.mark.repeat(10)
def test_pod_create_delete(env_pods):
    time.sleep(5)
    cmd_output = run_cmd(
        env_pods.v1,
        env_pods.namespace,
        env_pods.pods[0].name,
        ['ping', '-c', '3', env_pods.pods[1].ip],
    )
    assert packets_received(cmd_output, 3)


def test_pod_churn(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    pods = [PodInfo(unique_name('pod')) for _ in range(100)]
    try:
        for pod in pods:
            v1.create_namespaced_pod(namespace=namespace, body=pod.manifest)

        for pod in pods:
            wait_for(
                lambda pod_name=pod.name: pod_running(v1, pod_name, namespace)
            )

        for pod in pods:
            wait_for(
                lambda pod_name=pod.name: get_ip(v1, pod_name, namespace)
                is not None
            )

        ips = [get_ip(v1, pod.name, namespace) for pod in pods]
        assert all(ip is not None for ip in ips)
        assert len(ips) == len(set(ips))
    finally:
        for pod in pods:
            v1.delete_namespaced_pod(name=pod.name, namespace=namespace)
        for pod in pods:
            wait_for(
                lambda pod_name=pod.name: pod_gone(v1, namespace, pod_name)
            )
