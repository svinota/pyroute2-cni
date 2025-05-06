import asyncio

from pydantic import BaseModel, ConfigDict, PrivateAttr


class CNIInterface(BaseModel):
    name: str
    mac: str
    sandbox: str | None = None
    gateway: str | None = None


class CNIConfig(BaseModel):
    cniVersion: str
    interfaces: list[CNIInterface] | None = None


class CNIRequest(BaseModel):
    _ready: asyncio.Event = PrivateAttr()
    model_config = ConfigDict(extra="forbid")
    error: str = ''
    errno: int = 0
    cni: CNIConfig = CNIConfig(cniVersion='')
    rid: str | None = None
    netns: int = 0
    env: dict[str, str] = {}

    def __init__(self, **kwarg):
        super().__init__(**kwarg)
        self._ready = asyncio.Event()

    def merge(self, request):
        # just replace for now
        if request.cni is not None:
            self.cni = request.cni
        if request.env is not None:
            self.env = request.env

    async def ready(self):
        await asyncio.wait_for(self._ready.wait(), timeout=5.0)

    def set_ready(self):
        self._ready.set()
