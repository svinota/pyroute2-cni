import pytest

from kubernetes import client

from tests.test_functional.k8s import load_client, unique_name, wait_for, test_image


def test_pod_create_delete(pod_name=None, namespace=None):
    v1 = load_client()
    namespace = namespace if namespace is not None else 'default'
    pod_name = pod_name if pod_name is not None else unique_name('pod')
    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(name=pod_name),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name='sleep',
                    image=test_image(),
                    command=['sleep', 'inf'],
                )
            ],
            restart_policy='Never',
        ),
    )
    try:
        v1.create_namespaced_pod(namespace=namespace, body=pod)
        wait_for(
            lambda: v1.read_namespaced_pod(name=pod_name, namespace=namespace).status
            is not None
        )
    finally:
        v1.delete_namespaced_pod(name=pod_name, namespace=namespace)
        wait_for(lambda: _pod_gone(v1, namespace, pod_name))


def test_namespace_create_delete():
    v1 = load_client()
    namespace = unique_name('test-ns')
    body = client.V1Namespace(
        metadata=client.V1ObjectMeta(
            name=namespace,
            annotations={
                'pyroute2.org/vrf': '5000',
                'pyroute2.org/vxlan': '2000',
                'pyroute2.org/prefix': '10.2.3.0',
                'pyroute2.org/prefixlen': '24',
            },
        )
    )
    v1.create_namespace(body)
    test_pod_create_delete(namespace=namespace)
    try:
        ns = v1.read_namespace(name=namespace)
        assert ns.metadata is not None
        assert ns.metadata.annotations is not None
        assert ns.metadata.annotations.get('pyroute2.org/vrf') == '5000'
        assert ns.metadata.annotations.get('pyroute2.org/vxlan') == '2000'
    finally:
        v1.delete_namespace(name=namespace)
        wait_for(lambda: _namespace_gone(v1, namespace))


def _pod_gone(v1: client.CoreV1Api, namespace: str, name: str) -> bool:
    try:
        v1.read_namespaced_pod(name=name, namespace=namespace)
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False

def _namespace_gone(v1: client.CoreV1Api, name: str) -> bool:
    try:
        v1.read_namespace(name=name)
    except client.exceptions.ApiException as err:
        return err.status == 404
    return False
