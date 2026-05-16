from typing import Any, Protocol

from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.request import CNIRequest


class PluginProtocol(Protocol):
    async def resync(self, address_pool: AddressPool) -> None: ...

    async def cleanup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        p9server: Any,
    ) -> dict[str, Any]: ...

    async def setup(
        self,
        data: dict[str, Any],
        request: CNIRequest,
        pool: AddressPool,
        p9server: Any,
    ) -> dict[str, Any]: ...
