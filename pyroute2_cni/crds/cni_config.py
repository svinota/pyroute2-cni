import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CNIConfigStatus:
    ready: bool | None
    active: bool | None
    conditions: list[dict[str, Any]]


@dataclass(frozen=True)
class CNIConfig:
    name: str
    generation: int
    enabled: bool
    priority: int
    file_name: str
    plugins: list[dict[str, Any]]
    status: CNIConfigStatus | None

    def render(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            'apiVersion': 'cni.pyroute2.org/v1alpha1',
            'kind': 'CNIConfig',
            'metadata': {'name': self.name},
            'spec': {
                'enabled': self.enabled,
                'priority': self.priority,
                'fileName': self.file_name,
                'plugins': self.plugins,
            },
        }
        if self.status is not None:
            body['status'] = _render_status(self.status)
        return body


def _render_status(status: CNIConfigStatus) -> dict[str, Any]:
    body: dict[str, Any] = {}
    if status.ready is not None:
        body['ready'] = status.ready
    if status.active is not None:
        body['active'] = status.active
    if status.conditions:
        body['conditions'] = status.conditions
    return body


def parse_cni_config(item: dict[str, Any]) -> CNIConfig:
    metadata = item.get('metadata') or {}
    status = item.get('status') or None
    spec = item.get('spec') or {}

    parsed_status: CNIConfigStatus | None = None
    if isinstance(status, dict):
        parsed_status = CNIConfigStatus(
            ready=status.get('ready'),
            active=status.get('active'),
            conditions=list(status.get('conditions') or []),
        )

    return CNIConfig(
        name=str(metadata.get('name') or ''),
        generation=int(metadata.get('generation') or 0),
        enabled=bool(spec.get('enabled', False)),
        priority=int(spec.get('priority', 0)),
        file_name=str(spec['fileName']),
        plugins=[dict(plugin) for plugin in (spec.get('plugins') or [])],
        status=parsed_status,
    )


def default_cni_config() -> CNIConfig:
    conflist = json.loads(
        Path('/pyroute2-cni/05-chain.conflist').read_text(encoding='utf-8')
    )
    return CNIConfig(
        name=str(conflist.get('name') or 'cbr0'),
        generation=0,
        enabled=True,
        priority=0,
        file_name='99-pyroute2.conflist',
        plugins=[dict(plugin) for plugin in (conflist.get('plugins') or [])],
        status=CNIConfigStatus(ready=None, active=None, conditions=[]),
    )
