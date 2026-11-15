import time
import uuid

from kubernetes.stream import stream

from kubernetes import client


def packets_received(output, amount):
    step_1 = [x for x in output.split('\n') if 'packets received' in x][0]
    step_2 = step_1.split(',')[1]
    step_3 = step_2.split()[0]
    received = int(step_3)
    return received >= amount


def run_cmd(
    v1: client.CoreV1Api, namespace: str, name: str, command: list[str]
) -> str:
    return run_cmd_in_container(v1, namespace, name, None, command)


def run_cmd_in_container(
    v1: client.CoreV1Api,
    namespace: str,
    name: str,
    container: None | str,
    command: list[str],
) -> str:
    max_attempts = 10
    for i in range(max_attempts):
        try:
            return stream(
                v1.connect_get_namespaced_pod_exec,
                name=name,
                namespace=namespace,
                container=container,
                command=command,
                stderr=True,
                stdin=False,
                stdout=True,
                tty=False,
            )
        except client.exceptions.ApiException as err:
            if err.status != 0 or i == (max_attempts - 1):
                raise err
        time.sleep(1)
    raise RuntimeError()


def get_ip(v1: client.CoreV1Api, name: str, namespace: str) -> str | None:
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return pod.status.pod_ip if pod.status is not None else None


def pod_running(v1: client.CoreV1Api, name: str, namespace: str) -> bool:
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return pod.status is not None and pod.status.phase == 'Running'


def get_node_name(
    v1: client.CoreV1Api, name: str, namespace: str
) -> str | None:
    pod = v1.read_namespaced_pod(name=name, namespace=namespace)
    return pod.spec.node_name if pod.spec is not None else None


def get_mac(v1: client.CoreV1Api, name: str, namespace: str) -> str:
    output = run_cmd(
        v1, name=name, namespace=namespace, command=['ip', '-o', 'link']
    )
    for line in output.split('\n'):
        if 'link/ether' in line:
            tokens = line.split()
            return tokens[tokens.index('link/ether') + 1]
    return ''


def pod_gone(v1: client.CoreV1Api, namespace: str, name: str) -> bool:
    try:
        v1.read_namespaced_pod(name=name, namespace=namespace)
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False


def namespace_gone(v1: client.CoreV1Api, name: str) -> bool:
    try:
        v1.read_namespace(name=name)
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False


def vrd_gone(custom_api: client.CustomObjectsApi, name: str) -> bool:
    try:
        custom_api.get_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', name
        )
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False


def vrb_gone(custom_api: client.CustomObjectsApi, name: str) -> bool:
    try:
        custom_api.get_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomainbindings', name
        )
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
