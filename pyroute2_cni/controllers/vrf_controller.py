import logging
import os
from configparser import ConfigParser
from dataclasses import dataclass

from kubernetes.client.exceptions import ApiException
from pyroute2 import AsyncIPRoute

from pyroute2_cni.address_pool import AddressPool
from pyroute2_cni.controllers.base_crd_controller import BaseCRDWatchController
from pyroute2_cni.crds.vrf_domain import (
    VRFAttachment,
    VRFDomain,
    parse_vrf_domain,
)
from pyroute2_cni.crds.vrf_node_config import (
    VRFNodeConfig,
    parse_vrf_node_config,
)
from pyroute2_cni.firewall import FirewallManager
from pyroute2_cni.frr_manager import FRRManager


def set_sysctl(config: dict[str, int]) -> None:
    for path, value in config.items():
        with open(f'/proc/sys/{path.replace(".", "/")}', 'w') as f:
            f.write(str(value))


@dataclass
class VTEPInfo:
    ifname: str
    local: str
    link: int


class VRFController(BaseCRDWatchController[VRFDomain]):
    plural = 'vrfdomains'
    watch_name = 'vrfdomain'

    def __init__(
        self,
        config: ConfigParser,
        address_pool: AddressPool,
        frr_manager: FRRManager,
    ) -> None:
        super().__init__()
        self.config = config
        self.firewall = FirewallManager(config)
        self.address_pool = address_pool
        self.frr_manager = frr_manager
        self.host_link: int = 0
        self.host_src: str = ''
        self.host_ifname: str = ''
        self.node_name = os.environ.get('NODE_NAME', '')
        if not self.node_name:
            raise RuntimeError('node name is not set')

    def _parse_payload(self, obj: dict[str, object]) -> VRFDomain:
        return parse_vrf_domain(obj)

    async def remove_vrf(self, domain: VRFDomain) -> None:
        logging.info(f'Remove VRF {domain.vrf}')
        vrf_ifname = f'vrf-{domain.vrf}'
        async with AsyncIPRoute() as ipr:
            await ipr.ensure(ipr.link, present=False, ifname=vrf_ifname)
        await self.frr_manager.reload({domain.vrf: domain}, set())

    async def remove_vni(
        self, domain: VRFDomain, attachment: VRFAttachment, prefix: str
    ) -> None:
        l2vx_ifname = f'{prefix}vx-{attachment.vni}'
        l2br_ifname = f'{prefix}br-{domain.vrf}'
        async with AsyncIPRoute() as ipr:
            await ipr.ensure(ipr.link, present=False, ifname=l2br_ifname)
            await ipr.ensure(ipr.link, present=False, ifname=l2vx_ifname)

    async def ensure_vrf(self, domain: VRFDomain) -> int:
        logging.info(f'Ensure VRF: {domain}')
        await self.frr_manager.reload({}, set())
        vrf_ifname = f'vrf-{domain.vrf}'
        async with AsyncIPRoute() as ipr:
            return (
                await ipr.ensure(
                    ipr.link,
                    present=True,
                    ifname=vrf_ifname,
                    kind='vrf',
                    vrf_table=domain.table,
                    state='up',
                )
            )[0].get('index')

    async def _fetch_vtep(
        self, domain: VRFDomain, attachment: VRFAttachment
    ) -> VTEPInfo:
        #
        # fetch all the interfaces info
        #
        async with AsyncIPRoute() as ipr:
            links = dict(
                [(x.get('ifname'), x) async for x in await ipr.link('dump')]
            )

        try:
            response = (
                self.frr_manager.vrf_custom_api.list_cluster_custom_object(
                    'cni.pyroute2.org', 'v1alpha1', 'vrfnodeconfigs'
                )
            )
            node_config: VRFNodeConfig | None = None
            for item in response.get('items', []):
                node_config = parse_vrf_node_config(item)
                if node_config.node_ref.name == self.node_name:
                    break
            if node_config is None:
                raise KeyError('nodeRef')
            #
            # Iterate through the definitions and pick the first matching
            #
            interfaces = sorted(
                (
                    x
                    for x in node_config.interfaces
                    if x.name is None or x.name in links
                ),
                key=lambda x: x.name is None,
            )

            for item in interfaces:
                if item.name in links:
                    return VTEPInfo(
                        ifname=item.name,
                        local=item.local,
                        link=links[item.name].get('index'),
                    )
        except ApiException as e:
            status = (
                f'failed to read VRFNodeConfig node={self.node_name} '
                f'type={type(e)} status={e.status}'
            )
        except Exception as e:
            status = (
                f'failed to read VRFNodeConfig node={self.node_name} '
                f'type={type(e)} error={e}'
            )
        logging.warning(status)
        logging.info('falling back to netlink defaults')
        return VTEPInfo(
            ifname=self.host_ifname, local=self.host_src, link=self.host_link
        )

    async def ensure_vni(
        self,
        domain: VRFDomain,
        attachment: VRFAttachment,
        prefix: str,
        vrf_idx: int,
    ) -> int:
        vx_ifname = f'{prefix}vx-{attachment.vni}'
        br_ifname = f'{prefix}br-{domain.vrf}'
        logging.info(f'ensure attachment: {attachment}')
        br_idx = 0
        async with AsyncIPRoute() as ipr:
            links = dict(
                [(x.get('ifname'), x) async for x in await ipr.link('dump')]
            )
            br_idx = links.get(br_ifname, {}).get('index') or (
                await ipr.ensure(
                    ipr.link,
                    present=True,
                    ifname=br_ifname,
                    kind='bridge',
                    state='up',
                )
            )[0].get('index')

            #
            # NB: vxlan_link is the output device for VXLAN, not a
            #     master device; the master device will be the bridge
            #
            vtep_info = await self._fetch_vtep(domain, attachment)
            logging.info(f'vtep info: {vtep_info}')
            vx_idx = links.get(vx_ifname, {}).get('index') or (
                await ipr.ensure(
                    ipr.link,
                    present=True,
                    ifname=vx_ifname,
                    kind='vxlan',
                    vxlan_link=vtep_info.link,
                    vxlan_id=attachment.vni,
                    vxlan_port=attachment.port,
                    vxlan_local=vtep_info.local,
                    vxlan_learning=0,
                    state='up',
                )
            )[0].get('index')
            await ipr.link('set', index=br_idx, master=vrf_idx)
            await ipr.link('set', index=vx_idx, master=br_idx)
        set_sysctl({f'net.ipv4.conf.{br_ifname}.rp_filter': 0})
        return br_idx

    async def ensure(self, domain: VRFDomain) -> None:
        vrf_idx = await self.ensure_vrf(domain)
        bridges: dict[str, int] = {}
        for attachment in domain.attachments:
            match attachment.kind:
                case 'l2vni':
                    bridges['l2vni'] = await self.ensure_vni(
                        domain, attachment, 'l2', vrf_idx
                    )
                case 'l3vni':
                    bridges['l3vni'] = await self.ensure_vni(
                        domain, attachment, 'l3', vrf_idx
                    )
                case _:
                    pass
        await self.firewall.ensure_vrf_firewall(domain)

    async def reconcile_firewall(self) -> int:
        counter = 0
        for domain in self.frr_manager.vrf_domain_items().values():
            await self.firewall.ensure_vrf_firewall(domain)
            counter += 1
        return counter

    async def remove(self, domain: VRFDomain) -> None:
        for attachment in domain.attachments:
            match attachment.kind:
                case 'l2vni':
                    await self.remove_vni(domain, attachment, 'l2')
                case 'l3vni':
                    await self.remove_vni(domain, attachment, 'l3')
                case _:
                    pass
        await self.remove_vrf(domain)
        await self.firewall.remove_vrf_firewall(domain)

    async def make_default_vrf(self) -> VRFDomain:
        default_vrf = int(self.config['default']['vrf'])
        default_prefix = self.config['default']['prefix']
        default_prefixlen = int(self.config['default']['prefixlen'])
        domain = VRFDomain(
            name=f'vrf-{default_vrf}',
            vrf=default_vrf,
            table=default_vrf,
            prefix=default_prefix,
            prefixlen=default_prefixlen,
            ipblocklen=int(self.config['default']['ipblocklen']),
            attachments=[
                VRFAttachment(
                    kind=self.config['default']['system_vrf_type'],
                    vni=default_vrf,
                    port=4789,
                )
            ],
        )
        body = domain.render()
        try:
            self.frr_manager.vrf_custom_api.create_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', body
            )
        except ApiException as e:
            if e.status != 409:
                raise
        return domain

    async def resync(self) -> None:
        async with AsyncIPRoute() as ipr:
            logging.info('Trying to load VRF module')
            (vrf1,) = await ipr.ensure(
                ipr.link, present=True, ifname='vrf-1', kind='vrf', vrf_table=1
            )
            await ipr.ensure(ipr.link, present=False, index=vrf1['index'])
            logging.info('Trying to calculate host_if')
            default_route = await ipr.route('get', dst='1.1.1.1')
            self.host_link = default_route[0].get('oif')
            self.host_src = default_route[0].get('prefsrc') or '127.0.0.1'
            self.host_ifname = (await ipr.link('get', index=self.host_link))[
                0
            ].get('ifname')
            logging.info(
                f'Host discovery: {self.host_link}:'
                f'{self.host_ifname}:{self.host_src}'
            )
        logging.info('Setting sysctl variables')
        set_sysctl(
            {
                'net.ipv4.conf.all.rp_filter': 0,
                'net.vrf.strict_mode': 1,
                'net.ipv4.tcp_l3mdev_accept': 1,
                'net.ipv4.udp_l3mdev_accept': 1,
            }
        )

        domains: dict[int, VRFDomain] = self.frr_manager.vrf_domain_items()
        default_vrf = int(self.config['default']['vrf'])
        if default_vrf not in domains:
            domains[default_vrf] = await self.make_default_vrf()
        vrfs: list[int] = [default_vrf] + list(
            filter(lambda x: x != default_vrf, sorted(domains))
        )
        sorted_domains = dict(((k, domains[k]) for k in vrfs))
        for vrf, domain in sorted_domains.items():
            if domain.network is None:
                continue
            logging.info(f'VRFDomain: {domain.vrf}->{domain.network}')
            await self.ensure(domain)
