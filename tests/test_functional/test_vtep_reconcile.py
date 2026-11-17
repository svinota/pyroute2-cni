from functools import partial

import pytest

from kubernetes import client

from .utils import (
    get_node_name,
    packets_received,
    pod_gone,
    run_cmd,
    run_cmd_in_container,
    wait_for,
)

VTEP_IFNAME = 'l3vx-50200'
CNI_NAMESPACE = 'pyroute2-cni'
FRR_CONTAINER = 'pyroute2-frr'
CNI_LABEL = 'app=pyroute2-cni'


def test_vtep_reconcile_after_cni_restart(env_pods):
    v1, namespace = env_pods.v1, env_pods.namespace
    src_pod, dst_pod = env_pods.pods

    src_node = get_node_name(v1, src_pod.name, namespace)
    dst_node = get_node_name(v1, dst_pod.name, namespace)
    if not src_node or not dst_node:
        pytest.skip('pod node placement unavailable')
    if src_node == dst_node:
        pytest.skip('pods are not on different nodes')

    cni_pod = _ready_cni_pod_on_node(v1, src_node)
    assert cni_pod is not None, f'no Ready CNI pod on node={src_node}'
    expected_local, uplink = _vtep_local_and_uplink(v1, cni_pod)
    frr_exec = partial(
        run_cmd_in_container, v1, CNI_NAMESPACE, cni_pod, FRR_CONTAINER
    )

    secondary_local = '198.18.255.254'
    if secondary_local == expected_local:
        secondary_local = '198.18.255.253'
    secondary_cidr = f'{secondary_local}/32'

    try:
        # 1. Add a secondary address to the affected node's uplink.
        command = ['ip', 'addr', 'add', secondary_cidr, 'dev', uplink]
        output = frr_exec(command)
        assert not output.strip(), f'{command}: {output}'
        addresses = frr_exec(['ip', '-o', 'addr', 'show', 'dev', uplink])
        assert secondary_cidr in addresses.split(), addresses

        # 2. Change the existing VXLAN's local address.
        command = [
            'ip',
            'link',
            'set',
            'dev',
            VTEP_IFNAME,
            'type',
            'vxlan',
            'local',
            secondary_local,
        ]
        output = frr_exec(command)
        assert not output.strip(), f'{command}: {output}'

        assert _vtep_local_and_uplink(v1, cni_pod) == (secondary_local, uplink)

        # 3. Verify that cross-node workload traffic is broken.
        wait_for(
            lambda: packets_received(
                run_cmd(
                    v1,
                    namespace,
                    src_pod.name,
                    ['ping', '-c', '2', '-W', '1', dst_pod.ip],
                ),
                0,
            ),
            timeout=120.0,
            interval=2.0,
        )

        # 4. Restart the CNI pod on the affected node.
        v1.delete_namespaced_pod(name=cni_pod, namespace=CNI_NAMESPACE)
        wait_for(lambda: pod_gone(v1, CNI_NAMESPACE, cni_pod), timeout=120.0)

        wait_for(
            lambda: _ready_cni_pod_on_node(v1, src_node) is not None,
            timeout=180.0,
            interval=2.0,
        )
        recovered_pod = _ready_cni_pod_on_node(v1, src_node)
        assert recovered_pod is not None

        wait_for(
            lambda: _vtep_local_and_uplink(v1, recovered_pod)
            == (expected_local, uplink),
            timeout=120.0,
            interval=2.0,
        )

        # 5. Verify that cross-node workload traffic recovers.
        wait_for(
            lambda: packets_received(
                run_cmd(
                    v1,
                    namespace,
                    src_pod.name,
                    ['ping', '-c', '3', '-W', '1', dst_pod.ip],
                ),
                3,
            ),
            timeout=180.0,
            interval=3.0,
        )
    finally:
        cleanup_pod = _ready_cni_pod_on_node(v1, src_node)
        if cleanup_pod is not None:
            try:
                run_cmd_in_container(
                    v1,
                    CNI_NAMESPACE,
                    cleanup_pod,
                    FRR_CONTAINER,
                    ['ip', 'addr', 'del', secondary_cidr, 'dev', uplink],
                )
            except Exception:
                pass


def _ready_cni_pod_on_node(v1: client.CoreV1Api, node_name: str) -> str | None:
    pods = v1.list_namespaced_pod(
        namespace=CNI_NAMESPACE,
        label_selector=CNI_LABEL,
        field_selector=f'spec.nodeName={node_name}',
    ).items
    for pod in pods:
        if pod.status is None or pod.status.phase != 'Running':
            continue
        for condition in pod.status.conditions or []:
            if (
                condition.type == 'Ready'
                and condition.status == 'True'
                and pod.metadata is not None
            ):
                return pod.metadata.name
    return None


def _vtep_local_and_uplink(
    v1: client.CoreV1Api, cni_pod_name: str
) -> tuple[str, str]:
    output = run_cmd_in_container(
        v1,
        CNI_NAMESPACE,
        cni_pod_name,
        FRR_CONTAINER,
        ['ip', '-d', 'link', 'show', 'dev', VTEP_IFNAME],
    )
    tokens = output.replace('\n', ' ').split()
    local = ''
    uplink = ''
    for index, token in enumerate(tokens):
        if token == 'local' and index + 1 < len(tokens):
            local = tokens[index + 1]
        if token == 'dev' and index + 1 < len(tokens):
            uplink = tokens[index + 1]
    if not local or not uplink:
        raise AssertionError(f'failed to parse vxlan info: {output}')
    return local, uplink
