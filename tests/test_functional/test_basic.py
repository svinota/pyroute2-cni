import os
import time
import uuid
from dataclasses import dataclass, field

import pytest
from kubernetes.stream import stream

from kubernetes import client, config


@dataclass(frozen=True)
class PodInfo:
    name: str
    ip: str | None = None
    mac: str | None = None
    manifest: client.V1Pod = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, 'manifest', _create_test_pod(self.name))


@dataclass(frozen=True)
class PodsEnv:
    v1: client.CoreV1Api
    namespace: str
    pods: list[PodInfo]


@dataclass
class NamespaceEnv:
    v1: client.CoreV1Api
    name: str
    manifest: client.V1Namespace = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, 'manifest', _create_test_namespace(self.name))


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
        wait_for(lambda: _namespace_gone(v1, namespace.name))


@pytest.fixture
def env_pods(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    pod_1 = PodInfo(unique_name('pod'))
    pod_2 = PodInfo(unique_name('pod'))
    try:
        v1.create_namespaced_pod(namespace=namespace, body=pod_1.manifest)
        v1.create_namespaced_pod(namespace=namespace, body=pod_2.manifest)
        wait_for(lambda: _pod_running(v1, pod_1.name, namespace))
        wait_for(lambda: _pod_running(v1, pod_2.name, namespace))
        wait_for(lambda: _get_ip(v1, pod_1.name, namespace) is not None)
        wait_for(lambda: _get_ip(v1, pod_2.name, namespace) is not None)
        ip_1 = _get_ip(v1, pod_1.name, namespace)
        ip_2 = _get_ip(v1, pod_2.name, namespace)
        mac_1 = _get_mac(v1, pod_1.name, namespace)
        mac_2 = _get_mac(v1, pod_2.name, namespace)
        object.__setattr__(pod_1, 'ip', ip_1)
        object.__setattr__(pod_2, 'ip', ip_2)
        object.__setattr__(pod_1, 'mac', mac_1)
        object.__setattr__(pod_2, 'mac', mac_2)
        yield PodsEnv(v1, namespace, [pod_1, pod_2])
    finally:
        v1.delete_namespaced_pod(name=pod_1.name, namespace=namespace)
        v1.delete_namespaced_pod(name=pod_2.name, namespace=namespace)
        wait_for(lambda: _pod_gone(v1, namespace, pod_1.name))
        wait_for(lambda: _pod_gone(v1, namespace, pod_2.name))


def packets_received(output, amount):
    step_1 = [x for x in output.split('\n') if 'packets received' in x][0]
    step_2 = step_1.split(',')[1]
    step_3 = step_2.split()[0]
    received = int(step_3)
    return received == amount


@pytest.mark.repeat(10)
def test_pod_create_delete(env_pods):
    time.sleep(5)
    cmd_output = _run_cmd(
        env_pods.v1,
        env_pods.namespace,
        env_pods.pods[0].name,
        ['ping', '-c', '3', env_pods.pods[1].ip],
    )
    assert packets_received(cmd_output, 3)


def test_pod_churn(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    pods = [PodInfo(unique_name('pod')) for _ in range(200)]
    try:
        for pod in pods:
            v1.create_namespaced_pod(namespace=namespace, body=pod.manifest)

        for pod in pods:
            wait_for(lambda pod_name=pod.name: _pod_running(v1, pod_name, namespace))

        for pod in pods:
            wait_for(lambda pod_name=pod.name: _get_ip(v1, pod_name, namespace) is not None)

        ips = [
            _get_ip(v1, pod.name, namespace)
            for pod in pods
        ]
        assert all(ip is not None for ip in ips)
        assert len(ips) == len(set(ips))
    finally:
        for pod in pods:
            v1.delete_namespaced_pod(name=pod.name, namespace=namespace)
        for pod in pods:
            wait_for(lambda pod_name=pod.name: _pod_gone(v1, namespace, pod_name))


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
            'attachments': [
                {'type': 'l3vni', 'port': 4789, 'vni': 50200},
            ],
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
            wait_for(lambda pod_name=pod.name: _pod_running(v1, pod_name, namespace))

        for pod in pods:
            wait_for(lambda pod_name=pod.name: _get_ip(v1, pod_name, namespace) is not None)

        ipblocks = _list_ipblocks_for_vrf(custom_api, 200)
        assert len(ipblocks) == 6
        assert all(_ipblock_gateway_count(block) == 1 for block in ipblocks)

        for pod in pods:
            v1.delete_namespaced_pod(name=pod.name, namespace=namespace)
        for pod in pods:
            wait_for(lambda pod_name=pod.name: _pod_gone(v1, namespace, pod_name))

        wait_for(lambda: not _list_ipblocks_for_vrf(custom_api, 200))
    finally:
        custom_api.delete_cluster_custom_object(
            'cni.pyroute2.org',
            'v1alpha1',
            'vrfdomainbindings',
            vrfdomainbinding_name,
        )
        custom_api.delete_cluster_custom_object(
            'cni.pyroute2.org',
            'v1alpha1',
            'vrfdomains',
            vrfdomain_name,
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


def _not_test_namespace_create_delete(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    try:
        ns = v1.read_namespace(name=namespace)
        assert ns.metadata is not None
        assert ns.metadata.annotations is not None
        assert ns.metadata.annotations.get('pyroute2.org/vrf') == '5000'
        assert ns.metadata.annotations.get('pyroute2.org/l2vni') == '2000'
    finally:
        pass


def _get_ip(v1: client.CoreV1Api, name: str, namespace: str) -> str | None:
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return pod.status.pod_ip if pod.status is not None else None


def _pod_running(v1: client.CoreV1Api, name: str, namespace: str) -> bool:
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return pod.status is not None and pod.status.phase == 'Running'


def _get_mac(v1: client.CoreV1Api, name: str, namespace: str) -> str:
    output = stream(
        v1.connect_get_namespaced_pod_exec,
        name=name,
        namespace=namespace,
        command=['ip', '-o', 'link'],
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )
    for line in output.split('\n'):
        if 'link/ether' in line:
            tokens = line.split()
            return tokens[tokens.index('link/ether') + 1]
    return ''


def _pod_gone(v1: client.CoreV1Api, namespace: str, name: str) -> bool:
    try:
        v1.read_namespaced_pod(name=name, namespace=namespace)
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False


def _run_cmd(
    v1: client.CoreV1Api, namespace: str, name: str, command: list[str]
) -> str:
    return stream(
        v1.connect_get_namespaced_pod_exec,
        name=name,
        namespace=namespace,
        command=command,
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )


def _check_frr_status(v1: client.CoreV1Api) -> str:
    frr_pod_name = next(
        pod.metadata.name
        for pod in v1.list_namespaced_pod(namespace='pyroute2-cni').items
        if pod.metadata is not None
        and pod.metadata.name is not None
        and pod.metadata.name.startswith('pyroute2-cni')
        and pod.spec is not None
        and pod.spec.containers is not None
        and any(
            container.name == 'pyroute2-frr'
            for container in pod.spec.containers
        )
    )
    return stream(
        v1.connect_get_namespaced_pod_exec,
        name=frr_pod_name,
        namespace='pyroute2-cni',
        container='pyroute2-frr',
        command=['vtysh', '-c', 'show bgp l2vpn evpn route type 5'],
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )


def _create_test_namespace(name: str) -> client.V1Namespace:
    return client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=name, labels={'pyroute2.org/test': 'true'}
        )
    )


def _create_test_pod(name: str) -> client.V1Pod:
    pod_anti_affinity = client.V1PodAntiAffinity(
        preferred_during_scheduling_ignored_during_execution=[
            client.V1WeightedPodAffinityTerm(
                weight=100,
                pod_affinity_term=client.V1PodAffinityTerm(
                    label_selector=client.V1LabelSelector(
                        match_labels={'app': 'test-pod-create-delete'}
                    ),
                    topology_key='kubernetes.io/hostname',
                ),
            )
        ]
    )
    return client.V1Pod(
        metadata=client.V1ObjectMeta(
            name=name,
            labels={
                'app': 'test-pod-create-delete',
                'pyroute2.org/test': 'true',
            },
        ),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name='sleep',
                    image=os.environ.get(
                        'PYROUTE2_CNI_TEST_IMAGE', 'busybox:1.36'
                    ),
                    command=[
                        'sh',
                        '-c',
                        'trap : TERM INT; sleep infinity & wait',
                    ],
                )
            ],
            affinity=client.V1Affinity(pod_anti_affinity=pod_anti_affinity),
            restart_policy='Never',
        ),
    )


def _namespace_gone(v1: client.CoreV1Api, name: str) -> bool:
    try:
        v1.read_namespace(name=name)
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False


def unique_name(prefix: str) -> str:
    return f'{prefix}-{uuid.uuid4().hex[:8]}'


def wait_for(condition, timeout: float = 600.0, interval: float = 1.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            if condition():
                return
        except Exception as err:  # pragma: no cover - diagnostic path
            last_error = err
        time.sleep(interval)
    if last_error is not None:
        raise AssertionError(f'timed out waiting: {last_error}')
    raise AssertionError('timed out waiting')
