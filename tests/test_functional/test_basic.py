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


def test_pod_create_delete(env_pods):
    cmd_matches = 0
    frr_matches = 0
    cmd_output = _run_cmd(
        env_pods.v1,
        env_pods.namespace,
        env_pods.pods[0].name,
        ['ping', '-c', '1', env_pods.pods[1].ip],
    )
    frr_output = _check_frr_status(env_pods.v1)
    if '1 packets received' in cmd_output:
        cmd_matches += 1
    for pod in env_pods.pods:
        if pod.mac in frr_output:
            frr_matches += 1
    assert cmd_matches == 1
    assert frr_matches == 2


def test_namespace_create_delete(env_namespace):
    v1, namespace = env_namespace.v1, env_namespace.name
    try:
        ns = v1.read_namespace(name=namespace)
        assert ns.metadata is not None
        assert ns.metadata.annotations is not None
        assert ns.metadata.annotations.get('pyroute2.org/vrf') == '5000'
        assert ns.metadata.annotations.get('pyroute2.org/vxlan') == '2000'
    finally:
        pass


def _get_ip(v1: client.CoreV1Api, name: str, namespace: str) -> str | None:
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return pod.status.pod_ip if pod.status is not None else None


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
        command=['vtysh', '-c', 'show bgp l2vpn evpn route type 2'],
        stderr=True,
        stdin=False,
        stdout=True,
        tty=False,
    )


def _create_test_namespace(name: str) -> client.V1Namespace:
    return client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=name,
            annotations={
                'pyroute2.org/vrf': '5000',
                'pyroute2.org/vxlan': '2000',
                'pyroute2.org/prefix': '10.2.3.0',
                'pyroute2.org/prefixlen': '24',
            },
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
            name=name, labels={'app': 'test-pod-create-delete'}
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


def wait_for(condition, timeout: float = 60.0, interval: float = 1.0) -> None:
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
