from pyroute2 import AsyncIPRoute


class GatewayManager:
    async def ensure(self, index: int, address: str, prefixlen: int) -> None:
        async with AsyncIPRoute() as ipr:
            await ipr.ensure(
                ipr.addr,
                present=True,
                index=index,
                address=address,
                prefixlen=prefixlen,
            )
