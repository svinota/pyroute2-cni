from typing import Any, Protocol

from pyroute2_cni.request import CNIRequest


class PluginProtocol(Protocol):
    async def resync(self) -> None: ...

    async def watch_vrf_domains(self, queue: Any) -> None: ...

    async def cleanup(
        self, data: dict[str, Any], request: CNIRequest
    ) -> dict[str, Any]: ...

    async def setup(
        self, data: dict[str, Any], request: CNIRequest
    ) -> dict[str, Any]: ...
