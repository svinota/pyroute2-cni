import asyncio
from typing import Optional


class CNIProtocol(asyncio.Protocol):

    transport: asyncio.Transport

    def __init__(self, on_con_lost: asyncio.Future):
        self.on_con_lost = on_con_lost

    def data_received(self, data: bytes):
        return self.transport.write(data)

    def connection_made(self, transport: asyncio.Transport):
        self.transport = transport


class CNIServer:

    endpoint: asyncio.AbstractServer

    def __init__(
        self,
        path: str,
        use_event_loop: Optional[asyncio.AbstractEventLoop] = None
    ):
        self.event_loop = use_event_loop or asyncio.get_event_loop()
        self.connection_lost = self.event_loop.create_future()
        self.path = path

    async def setup_endpoint(self):
        self.endpoint = await self.event_loop.create_unix_server(
            lambda: CNIProtocol(self.connection_lost),
            path=self.path,
        )


async def main():
    server = CNIServer('sock')
    await server.setup_endpoint()
    await asyncio.sleep(600)


if __name__ == '__main__':
    asyncio.run(main())
