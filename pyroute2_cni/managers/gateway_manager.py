from configparser import ConfigParser

from pyroute2 import AsyncIPRoute

from pyroute2_cni.crds.vrf_domain import VRFDomain
from pyroute2_cni.managers.firewall_manager import FirewallManager


class GatewayManager:
    def __init__(self, config: ConfigParser):
        self.config = config
        self.firewall = FirewallManager(config)

    async def ensure(
        self,
        present: bool,
        domain: VRFDomain,
        index: int,
        address: str,
        prefixlen: int,
    ) -> None:
        async with AsyncIPRoute() as ipr:
            #
            # set up gateway address
            await ipr.ensure(
                ipr.addr,
                present=present,
                index=index,
                address=address,
                prefixlen=prefixlen,
            )
            #
            # set up routing policy to allow kubelet
            # to monitor pods in this VRF
            await ipr.ensure(
                ipr.rule,
                present=present,
                priority=32000,
                iifname='lo',
                dst=address,
                dst_len=prefixlen,
                table=domain.table or domain.vrf,
            )
