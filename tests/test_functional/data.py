import os
from dataclasses import dataclass, field

from kubernetes import client


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
    custom_api: client.CustomObjectsApi
    name: str
    manifest: client.V1Namespace = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, 'manifest', _create_test_namespace(self.name))


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
