from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class VRFNodeConfigNodeRef:
    name: str


@dataclass(frozen=True)
class VRFNodeConfigInterface:
    name: str
    local: str


@dataclass(frozen=True)
class VRFNodeConfigCondition:
    type: str
    status: str
    observed_generation: int
    reason: str
    message: str
    last_transition_time: datetime


@dataclass(frozen=True)
class VRFNodeConfigStatus:
    ready: bool | None
    route_reflectors_count: int | None
    interfaces_count: int | None
    conditions: list[VRFNodeConfigCondition]


@dataclass(frozen=True)
class VRFNodeConfig:
    name: str
    generation: int
    node_ref: VRFNodeConfigNodeRef
    router_id: str | None
    route_reflectors: list[str]
    interfaces: list[VRFNodeConfigInterface]
    status: VRFNodeConfigStatus | None

    def render(self) -> dict[str, Any]:
        spec: dict[str, Any] = {
            'nodeRef': {'name': self.node_ref.name},
            'interfaces': [
                {'name': item.name, 'local': item.local}
                for item in self.interfaces
            ],
        }
        if self.router_id is not None:
            spec['routerId'] = self.router_id
        if self.route_reflectors:
            spec['routeReflectors'] = list(self.route_reflectors)

        body: dict[str, Any] = {
            'apiVersion': 'cni.pyroute2.org/v1alpha1',
            'kind': 'VRFNodeConfig',
            'metadata': {'name': self.name},
            'spec': spec,
        }
        if self.status is not None:
            body['status'] = _render_status(self.status)
        return body


def _render_status(status: VRFNodeConfigStatus) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if status.ready is not None:
        body['ready'] = status.ready
    if status.route_reflectors_count is not None:
        body['routeReflectorsCount'] = status.route_reflectors_count
    if status.interfaces_count is not None:
        body['interfacesCount'] = status.interfaces_count
    if status.conditions:
        body['conditions'] = [
            {
                'type': item.type,
                'status': item.status,
                'observedGeneration': item.observed_generation,
                'reason': item.reason,
                'message': item.message,
                'lastTransitionTime': item.last_transition_time.isoformat(),
            }
            for item in status.conditions
        ]
    return body


def render_vrf_node_config_conditions(
    conditions: list[VRFNodeConfigCondition],
) -> list[dict[str, Any]]:
    return _render_status(
        VRFNodeConfigStatus(None, None, None, conditions)
    ).get('conditions', [])


def parse_vrf_node_config(item: dict[str, Any]) -> VRFNodeConfig:
    metadata = item.get('metadata') or {}
    spec = item.get('spec') or {}
    status = item.get('status') or None

    node_ref = spec.get('nodeRef') or {}
    interfaces = [
        VRFNodeConfigInterface(
            name=str(entry.get('name', '')), local=str(entry.get('local', ''))
        )
        for entry in spec.get('interfaces') or []
    ]

    parsed_status: VRFNodeConfigStatus | None = None
    if isinstance(status, dict):
        conditions = [
            VRFNodeConfigCondition(
                type=str(entry.get('type', '')),
                status=str(entry.get('status', '')),
                observed_generation=int(entry.get('observedGeneration', 0)),
                reason=str(entry.get('reason', '')),
                message=str(entry.get('message', '')),
                last_transition_time=datetime.fromisoformat(
                    str(entry.get('lastTransitionTime', ''))
                ),
            )
            for entry in status.get('conditions') or []
        ]
        parsed_status = VRFNodeConfigStatus(
            ready=status.get('ready'),
            route_reflectors_count=status.get('routeReflectorsCount'),
            interfaces_count=status.get('interfacesCount'),
            conditions=conditions,
        )

    return VRFNodeConfig(
        name=str(metadata.get('name') or ''),
        generation=int(metadata.get('generation') or 0),
        node_ref=VRFNodeConfigNodeRef(name=str(node_ref.get('name') or '')),
        router_id=(str(spec['routerId']) if spec.get('routerId') else None),
        route_reflectors=[
            str(item) for item in spec.get('routeReflectors') or []
        ],
        interfaces=interfaces,
        status=parsed_status,
    )
