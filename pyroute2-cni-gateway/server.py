import asyncio
from typing import Optional

from pydantic import BaseModel, ConfigDict, ValidationError


class CNIInterface(BaseModel):
    name: str
    mac: str
    sandbox: str | None = None
    gateway: str | None = None


class CNIConfig(BaseModel):
    cniVersion: str
    interfaces: list[CNIInterface] | None = None


class CNIRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str = ''
    errno: int = 0
    cni: CNIConfig | None = None
    rid: str | None = None
    env: dict[str, str] | None = None


class CNIProtocol(asyncio.Protocol):

    transport: asyncio.Transport

    def __init__(
        self, on_con_lost: asyncio.Future, registry: dict[str, CNIRequest]
    ):
        self.on_con_lost = on_con_lost
        self.registry = registry

    def error(self, spec: str):
        return self.transport.write(spec.encode('utf-8'))

    def data_received(self, data: bytes):
        # we have now two types of requests in the protocol.
        # 1. RID request -> returns request id
        # 2. CNI request -> returns CNI config by RID
        try:
            request = CNIRequest.model_validate_json(data)
        except ValidationError as err:
            return self.error(err.json())
        print(" >>> ", request)
        return self.transport.write(data)

    # do not annotate
    def connection_made(self, transport):
        self.transport = transport


class CNIServer:

    endpoint: asyncio.AbstractServer

    def __init__(
        self,
        path: str,
        use_event_loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.event_loop = use_event_loop or asyncio.get_event_loop()
        self.connection_lost = self.event_loop.create_future()
        self.path = path
        self.registry: dict[str, CNIRequest] = {}

    async def setup_endpoint(self):
        self.endpoint = await self.event_loop.create_unix_server(
            lambda: CNIProtocol(self.connection_lost, self.registry),
            path=self.path,
        )


async def main():
    server = CNIServer('sock')
    await server.setup_endpoint()
    await asyncio.sleep(600)


if __name__ == '__main__':
    asyncio.run(main())
