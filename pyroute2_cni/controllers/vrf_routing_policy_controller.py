import logging
from configparser import ConfigParser
from dataclasses import asdict

from pyroute2 import AsyncIPRoute

from pyroute2_cni.controllers.base_crd_controller import BaseCRDWatchController
from pyroute2_cni.crds.vrf_domain import parse_vrf_domain
from pyroute2_cni.crds.vrf_routing_policy import (
    VRFRoutingPolicy,
    parse_vrf_routing_policy,
)


class VRFRoutingPolicyController(BaseCRDWatchController[VRFRoutingPolicy]):
    plural = 'vrfroutingpolicies'
    watch_name = 'vrfroutingpolicy'

    def __init__(self, config: ConfigParser) -> None:
        super().__init__()
        self.config = config

    def _parse_payload(
        self, obj: dict[str, object]
    ) -> VRFRoutingPolicy | None:
        return parse_vrf_routing_policy(obj)

    async def ensure_rule(
        self, present: bool, policy: VRFRoutingPolicy
    ) -> None:
        logging.info(
            f'Ensure VRFRoutingPolicy present={present} '
            f'policy={policy.name}'
        )
        vrf_domain_table = 0
        try:
            response = self.custom_api.list_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
            )
            for item in response.get('items', []):
                vrf_domain = parse_vrf_domain(item)
                if vrf_domain.name == policy.vrf_domain_ref.name:
                    vrf_domain_table = vrf_domain.table
                    break
        except Exception as e:
            logging.error(f'VRFRoutingPolicy: failed to load VRFDomain: {e}')
        async with AsyncIPRoute() as ipr:
            for rule in policy.match:
                kwarg = {
                    x: y for x, y in asdict(rule).items() if y is not None
                }
                logging.info(
                    f'Rule table={vrf_domain_table} ' f'selector={kwarg}'
                )
                try:
                    await ipr.ensure(
                        ipr.rule,
                        present=present,
                        priority=11000,
                        table=vrf_domain_table,
                        **kwarg,
                    )
                except Exception as e:
                    logging.error(f'VRFRoutingPolicy: {e}')

    async def ensure(self, policy: VRFRoutingPolicy) -> None:
        await self.ensure_rule(present=True, policy=policy)

    async def remove(self, policy: VRFRoutingPolicy) -> None:
        await self.ensure_rule(present=False, policy=policy)
