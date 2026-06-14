from kubernetes import client

from .data import PodInfo
from .utils import get_ip, pod_gone, pod_running, unique_name, wait_for


def test_ipblock_gateways(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    custom_api = client.CustomObjectsApi()
    vrfdomain_name = unique_name('vrfdomain')
    vrfdomainbinding_name = unique_name('vrfdomainbinding')
    pods = [PodInfo(unique_name('pod')) for _ in range(30)]
    vrfdomain = {
        'apiVersion': 'cni.pyroute2.org/v1alpha1',
        'kind': 'VRFDomain',
        'metadata': {'name': vrfdomain_name},
        'spec': {
            'attachments': [{'type': 'l3vni', 'port': 4789, 'vni': 50200}],
            'ipblocklen': 29,
            'prefix': '10.150.0.0',
            'prefixlen': 16,
            'table': 2200,
            'vrf': 200,
        },
    }
    vrfdomainbinding = {
        'apiVersion': 'cni.pyroute2.org/v1alpha1',
        'kind': 'VRFDomainBinding',
        'metadata': {'name': vrfdomainbinding_name},
        'spec': {
            'namespaceRef': {'name': namespace},
            'vrfDomainRef': {'name': vrfdomain_name},
        },
    }
    try:
        custom_api.create_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', vrfdomain
        )
        custom_api.create_cluster_custom_object(
            'cni.pyroute2.org',
            'v1alpha1',
            'vrfdomainbindings',
            vrfdomainbinding,
        )

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
            wait_for(
                lambda pod_name=pod.name: pod_gone(v1, namespace, pod_name)
            )

        wait_for(lambda: not _list_ipblocks_for_vrf(custom_api, 200))
    finally:
        custom_api.delete_cluster_custom_object(
            'cni.pyroute2.org',
            'v1alpha1',
            'vrfdomainbindings',
            vrfdomainbinding_name,
        )
        custom_api.delete_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', vrfdomain_name
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
