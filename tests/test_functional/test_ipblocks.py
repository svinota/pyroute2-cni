from kubernetes import client

from .data import PodInfo
from .utils import get_ip, pod_gone, pod_running, unique_name, wait_for


def test_ipblock_gateways(env_namespace):
    v1, custom_api, namespace = (
        env_namespace.v1,
        env_namespace.custom_api,
        env_namespace.name,
    )
    pods = [PodInfo(unique_name('pod')) for _ in range(30)]

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

    ipblocks = _list_ipblocks_for_vrf(custom_api, 200)
    assert len(ipblocks) == 6
    assert all(_ipblock_gateway_count(block) == 1 for block in ipblocks)

    for pod in pods:
        v1.delete_namespaced_pod(name=pod.name, namespace=namespace)
    for pod in pods:
        wait_for(lambda pod_name=pod.name: pod_gone(v1, namespace, pod_name))

    wait_for(
        lambda: len(_list_ipblocks_for_vrf(custom_api, 200))
        == len(v1.list_node().items)
    )


def _list_ipblocks_for_vrf(
    custom_api: client.CustomObjectsApi, vrf_table: int
) -> list[dict]:
    items = custom_api.list_cluster_custom_object(
        'ipam.pyroute2.org', 'v1alpha1', 'ipblocks'
    ).get('items', [])
    result = []
    for item in items:
        metadata = item.get('metadata') or {}
        spec = item.get('spec') or {}
        status = item.get('status') or {}
        if not metadata.get('name', '').startswith(f'vrf-{vrf_table}-'):
            continue
        if spec.get('vrfTable') != vrf_table:
            continue
        result.append({'metadata': metadata, 'spec': spec, 'status': status})
    return result


def _ipblock_gateway_count(block: dict) -> int:
    allocations = block.get('status', {}).get('allocations') or {}
    return sum(1 for value in allocations.values() if value == 'gateway')
