from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CNIConfigSelectionActiveRef:
    name: str


@dataclass(frozen=True)
class CNIConfigSelectionStatus:
    observed_generation: int | None


@dataclass(frozen=True)
class CNIConfigSelection:
    name: str
    generation: int
    active_ref: CNIConfigSelectionActiveRef
    status: CNIConfigSelectionStatus | None

    def render(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            'apiVersion': 'cni.pyroute2.org/v1alpha1',
            'kind': 'CNIConfigSelection',
            'metadata': {'name': self.name},
            'spec': {'activeRef': {'name': self.active_ref.name}},
        }
        if self.status is not None:
            body['status'] = _render_status(self.status)
        return body


def _render_status(status: CNIConfigSelectionStatus) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if status.observed_generation is not None:
        body['observedGeneration'] = status.observed_generation
    return body


def parse_cni_config_selection(item: dict[str, Any]) -> CNIConfigSelection:
    metadata = item.get('metadata') or {}
    spec = item.get('spec') or {}
    status = item.get('status') or None

    parsed_status: CNIConfigSelectionStatus | None = None
    if isinstance(status, dict):
        parsed_status = CNIConfigSelectionStatus(
            observed_generation=status.get('observedGeneration')
        )

    active_ref = spec.get('activeRef') or {}
    return CNIConfigSelection(
        name=str(metadata.get('name') or ''),
        generation=int(metadata.get('generation') or 0),
        active_ref=CNIConfigSelectionActiveRef(
            name=str(active_ref.get('name') or '')
        ),
        status=parsed_status,
    )
