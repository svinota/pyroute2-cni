import asyncio
import logging
import os
import socket
import threading
from configparser import ConfigParser
from dataclasses import dataclass
from ipaddress import IPv4Network

from kubernetes.client.exceptions import ApiException
from pyroute2 import AsyncIPRoute

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import watch as k8s_watch  # type: ignore[attr-defined]

from .address_pool import AddressPool
from .firewall import FirewallManager
from .frr_manager import FRRManager
from .kubernetes import get_cluster_custom_object
from .vrf_domain import VRFAttachment, VRFDomain, parse_vrf_domain


def set_sysctl(config: dict[str, int]) -> None:
    for path, value in config.items():
        with open(f'/proc/sys/{path.replace(".", "/")}', 'w') as f:
            f.write(str(value))


@dataclass
class VTEPInfo:
    ifname: str
    local: str
    link: int


class VRFController:
    def __init__(
        self,
        config: ConfigParser,
        address_pool: AddressPool,
        frr_manager: FRRManager,
    ) -> None:
        self.config = config
        self.firewall = FirewallManager(config)
        self.address_pool = address_pool
        self.frr_manager = frr_manager
        self.vrf_custom_api = k8s_client.CustomObjectsApi()
        self.host_link: int = 0
        self.host_src: str = ''
        self.host_ifname: str = ''
        self.node_name = os.environ.get('NODE_NAME', '')
        if not self.node_name:
            raise RuntimeError('node name is not set')

    async def remove_vrf(self, domain: VRFDomain) -> None:
        vrf_ifname = f'vrf-{domain.vrf}'
        async with AsyncIPRoute() as ipr:
            await ipr.ensure(ipr.link, present=False, ifname=vrf_ifname)
        await self.frr_manager.reload(self._vrf_domain_items())

    async def remove_vni(
        self, domain: VRFDomain, attachment: VRFAttachment, prefix: str
    ) -> None:
        l2vx_ifname = f'{prefix}vx-{attachment.vni}'
        l2br_ifname = f'{prefix}br-{domain.vrf}'
        async with AsyncIPRoute() as ipr:
            await ipr.ensure(ipr.link, present=False, ifname=l2br_ifname)
            await ipr.ensure(ipr.link, present=False, ifname=l2vx_ifname)

    async def ensure_vrf(self, domain: VRFDomain) -> int:
        logging.info(f'ensure VRF: {domain}')
        await self.frr_manager.reload(self._vrf_domain_items())
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

    async def ensure_bridge_address(
        self, domain: VRFDomain, br_idx: int
    ) -> None:

        logging.info(f'ensure bridge address for domain: {domain}')
        async with AsyncIPRoute() as ipr:
            addresses: list[tuple[str, int]] = [
                (x.get('address'), x.get('prefixlen'))
                async for x in await ipr.addr(
                    'dump', index=br_idx, family=socket.AF_INET
                )
            ]
            prefix = domain.prefix or str(self.config['default']['prefix'])
            prefixlen = domain.prefixlen or int(
                self.config['default']['prefixlen']
            )
            if len(addresses) == 0:
                network = IPv4Network(f'{prefix}/{prefixlen}')
                address = await self.address_pool.allocate(
                    network, domain.ipblocklen, domain.vrf, is_gateway=True
                )
                await ipr.ensure(
                    ipr.addr,
                    present=True,
                    index=br_idx,
                    address=address,
                    prefixlen=prefixlen,
                )
            table = (
                domain.table
                if domain.table
                > int(self.config['default']['service_vrf_max'])
                else 254
            )
            await ipr.ensure(
                ipr.route,
                present=True,
                oif=br_idx,
                dst=prefix,
                dst_len=prefixlen,
                table=table,
            )

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
            obj = get_cluster_custom_object(
                'cni.pyroute2.org',
                'v1alpha1',
                'vrfnodeconfigs',
                self.node_name,
            )
            spec = obj.get('spec') or {}
            #
            # Iterate through the definitions and pick the first matching
            #
            interfaces = sorted(
                (
                    x
                    for x in spec.get('interfaces', [])
                    if x.get('name') is None or x.get('name') in links
                ),
                key=lambda x: x.get('name') is None,
            )

            for item in interfaces:
                if item.get('name') in links:
                    return VTEPInfo(
                        ifname=item.get('name'),
                        local=item.get('local'),
                        link=links[item.get('name')].get('index'),
                    )
        except ApiException as e:
            if e.status != 404:
                logging.warning(
                    'failed to read VRFNodeConfig for node %s, '
                    'falling back to netlink: %s',
                    self.node_name,
                    e,
                )
            else:
                logging.info(
                    'VRFNodeConfig for node %s not found, '
                    'falling back to netlink',
                    self.node_name,
                )
        except Exception as e:
            logging.warning(
                'failed to read VRFNodeConfig for node %s, '
                'falling back to netlink: %s',
                self.node_name,
                e,
            )

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
        for attachment in domain.attachments:
            match attachment.kind:
                case 'l2vni':
                    br_idx = await self.ensure_vni(
                        domain, attachment, 'l2', vrf_idx
                    )
                    await self.ensure_bridge_address(domain, br_idx)
                case 'l3vni':
                    await self.ensure_vni(domain, attachment, 'l3', vrf_idx)
                case _:
                    pass
        await self.firewall.ensure_system_firewall(domain)

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
        await self.firewall.remove_system_firewall(domain)

    def _vrf_domain_items(self) -> dict[int, VRFDomain]:
        response = self.vrf_custom_api.list_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
        )
        return dict(
            (
                (x.vrf, x)
                for x in (
                    parse_vrf_domain(item)
                    for item in response.get('items', [])
                )
            )
        )

    async def make_default_vrf(self) -> VRFDomain:
        default_vrf = int(self.config['default']['vrf'])
        default_prefix = self.config['default']['prefix']
        default_prefixlen = int(self.config['default']['prefixlen'])

        async with AsyncIPRoute() as ipr:
            logging.info('trying to calculate host_if')
            default_route = await ipr.route('get', dst='1.1.1.1')
            self.host_link = default_route[0].get('oif')
            self.host_src = default_route[0].get('prefsrc') or '127.0.0.1'
            self.host_ifname = (await ipr.link('get', index=self.host_link))[
                0
            ].get('ifname')
            logging.info(
                f'host discovery: {self.host_link}:'
                f'{self.host_ifname}:{self.host_src}'
            )

        domain = VRFDomain(
            name=f'vrf-{default_vrf}',
            vrf=default_vrf,
            table=default_vrf,
            prefix=default_prefix,
            prefixlen=default_prefixlen,
            ipblocklen=int(self.config['default']['ipblocklen']),
            attachments=[
                VRFAttachment(kind='l2vni', vni=default_vrf, port=4789)
            ],
        )
        body = domain.render()
        try:
            self.vrf_custom_api.create_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains', body
            )
        except ApiException as e:
            if e.status != 409:
                raise
        return domain

    async def resync(self) -> None:
        set_sysctl(
            {
                'net.ipv4.conf.all.rp_filter': 0,
                'net.vrf.strict_mode': 1,
                'net.ipv4.tcp_l3mdev_accept': 1,
                'net.ipv4.udp_l3mdev_accept': 1,
            }
        )
        async with AsyncIPRoute() as ipr_main:
            (vrf1,) = await ipr_main.ensure(
                ipr_main.link,
                present=True,
                ifname='vrf-1',
                kind='vrf',
                vrf_table=1,
            )
            await ipr_main.ensure(
                ipr_main.link, present=False, index=vrf1['index']
            )
        domains: dict[int, VRFDomain] = self._vrf_domain_items()
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
            logging.info(f'vrfdomain: {domain.vrf}->{domain.network}')
            await self.ensure(domain)

    def _watch_worker(
        self,
        queue: asyncio.Queue[tuple[str, VRFDomain] | None],
        loop: asyncio.AbstractEventLoop,
        stop_event: threading.Event,
    ) -> None:
        try:
            k8s_config.load_incluster_config()  # type: ignore[attr-defined]
        except Exception as e:
            logging.error(f'error starting vrfdomain watch: {e}')
            loop.call_soon_threadsafe(queue.put_nowait, None)
            return

        watcher = k8s_watch.Watch()
        resource_version = ''

        def refresh_resource_version() -> str:
            response = self.vrf_custom_api.list_cluster_custom_object(
                'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
            )
            metadata = response.get('metadata') or {}
            rv = str(metadata.get('resourceVersion') or '')
            logging.info('vrfdomain watch relisted at rv=%s', rv)
            return rv

        try:
            while not stop_event.is_set():
                try:
                    for event in watcher.stream(
                        self.vrf_custom_api.list_cluster_custom_object,
                        'cni.pyroute2.org',
                        'v1alpha1',
                        'vrfdomains',
                        timeout_seconds=30,
                        resource_version=resource_version or None,
                    ):
                        if stop_event.is_set():
                            break
                        event_type = event.get('type')
                        obj = event.get('object')
                        if not obj:
                            continue
                        metadata = obj.get('metadata') or {}
                        rv = str(metadata.get('resourceVersion') or '')
                        if rv:
                            resource_version = rv
                        domain = parse_vrf_domain(obj)
                        if event_type in {'ADDED', 'MODIFIED', 'DELETED'}:
                            loop.call_soon_threadsafe(
                                queue.put_nowait, (event_type, domain)
                            )
                except ApiException as e:
                    if e.status == 410 or 'Expired' in str(e):
                        logging.warning(
                            'vrfdomain watch expired rv=%s, resetting: %s',
                            resource_version,
                            e,
                        )
                        resource_version = refresh_resource_version()
                        continue
                    logging.warning(
                        'vrfdomain watch api exception, restarting rv=%s: %s',
                        resource_version,
                        e,
                    )
                except Exception as e:
                    logging.warning(
                        'vrfdomain watch failed, restarting rv=%s: %s',
                        resource_version,
                        e,
                    )
        finally:
            watcher.stop()
            loop.call_soon_threadsafe(queue.put_nowait, None)

    async def watch(
        self,
        queue: asyncio.Queue[tuple[str, VRFDomain] | None],
        ready: asyncio.Event | None = None,
    ) -> None:
        loop = asyncio.get_running_loop()
        stop_event = threading.Event()
        worker = threading.Thread(
            target=self._watch_worker,
            args=(queue, loop, stop_event),
            daemon=True,
        )
        try:
            await self.firewall.setup()
            await self.resync()
            if ready is not None:
                ready.set()
        except Exception as e:
            logging.warning(
                'vrfdomain watch initial list failed, continuing: %s', e
            )

        worker.start()
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                event_type, domain = event
                if event_type == 'ADDED':
                    await self.ensure(domain)
                elif event_type == 'MODIFIED':
                    await self.ensure(domain)
                elif event_type == 'DELETED':
                    await self.remove(domain)
        finally:
            stop_event.set()
            worker.join(timeout=5)
