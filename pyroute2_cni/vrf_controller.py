import asyncio
import logging
import socket
import threading
from configparser import ConfigParser
from ipaddress import IPv4Network

from kubernetes.client.exceptions import ApiException
from pyroute2 import AsyncIPRoute

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config
from kubernetes import watch as k8s_watch  # type: ignore[attr-defined]

from .address_pool import AddressPool
from .firewall import FirewallManager
from .frr_manager import FRRManager
from .vrf_domain import VRFAttachment, VRFDomain, parse_vrf_domain


def set_sysctl(config: dict[str, int]) -> None:
    for path, value in config.items():
        with open(f'/proc/sys/{path.replace(".", "/")}', 'w') as f:
            f.write(str(value))


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

    async def remove_l2vni(
        self, domain: VRFDomain, attachment: VRFAttachment
    ) -> None:
        vrf_ifname = f'vrf-{domain.vrf}'
        l2vx_ifname = f'l2vx-{attachment.vni}'
        l2ibr_ifname = f'l2ibr-{attachment.vni}'
        async with AsyncIPRoute() as ipr:
            await ipr.ensure(ipr.link, present=False, ifname=vrf_ifname)
            await ipr.ensure(ipr.link, present=False, ifname=l2ibr_ifname)
            await ipr.ensure(ipr.link, present=False, ifname=l2vx_ifname)
        await self.frr_manager.reload(self._vrf_domain_items())
        await self.firewall.remove_system_firewall(domain, attachment)

    async def ensure_l2vni(
        self, domain: VRFDomain, attachment: VRFAttachment
    ) -> None:
        vrf_table = domain.table if domain.table is not None else domain.vrf
        vrf_ifname = f'vrf-{domain.vrf}'
        l2vx_ifname = f'l2vx-{attachment.vni}'
        l2ibr_ifname = f'l2ibr-{attachment.vni}'
        await self.frr_manager.reload(self._vrf_domain_items())
        logging.info(f'ensure attachment: {attachment}')
        async with AsyncIPRoute() as ipr:
            links = dict(
                [(x.get('ifname'), x) async for x in await ipr.link('dump')]
            )
            vrf_idx = links.get(vrf_ifname, {}).get('index') or (
                await ipr.ensure(
                    ipr.link,
                    present=True,
                    ifname=vrf_ifname,
                    kind='vrf',
                    vrf_table=vrf_table,
                    state='up',
                )
            )[0].get('index')
            l2ibr_idx = links.get(l2ibr_ifname, {}).get('index') or (
                await ipr.ensure(
                    ipr.link,
                    present=True,
                    ifname=l2ibr_ifname,
                    kind='bridge',
                    state='up',
                )
            )[0].get('index')

            addresses: list[tuple[str, int]] = [
                (x.get('address'), x.get('prefixlen'))
                async for x in await ipr.addr(
                    'dump', index=l2ibr_idx, family=socket.AF_INET
                )
            ]
            prefix = domain.prefix or str(self.config['default']['prefix'])
            prefixlen = domain.prefixlen or int(
                self.config['default']['prefixlen']
            )
            if len(addresses) == 0:
                network = IPv4Network(f'{prefix}/{prefixlen}')
                address = await self.address_pool.allocate(
                    network, domain.vrf, is_gateway=True
                )
                await ipr.ensure(
                    ipr.addr,
                    present=True,
                    index=l2ibr_idx,
                    address=address,
                    prefixlen=prefixlen,
                )
            await ipr.ensure(
                ipr.route,
                present=True,
                oif=l2ibr_idx,
                dst=prefix,
                dst_len=prefixlen,
                table=(
                    vrf_table
                    if vrf_table
                    > int(self.config['default']['service_vrf_max'])
                    else 254
                ),
            )

            l2vx_idx = links.get(l2vx_ifname, {}).get('index') or (
                await ipr.ensure(
                    ipr.link,
                    present=True,
                    ifname=l2vx_ifname,
                    kind='vxlan',
                    vxlan_link=links[attachment.dev],
                    vxlan_id=attachment.vni,
                    vxlan_port=attachment.port,
                    vxlan_local=await attachment.fetch_local(),
                    vxlan_learning=0,
                    state='up',
                )
            )[0].get('index')
            await ipr.link('set', index=l2ibr_idx, master=vrf_idx)
            await ipr.link('set', index=l2vx_idx, master=l2ibr_idx)
        await self.firewall.ensure_system_firewall(domain, attachment)
        set_sysctl({f'net.ipv4.conf.{l2ibr_ifname}.rp_filter': 0})

    async def ensure(self, domain: VRFDomain) -> None:
        for attachment in domain.attachments:
            match attachment.kind:
                case 'l2vni':
                    await self.ensure_l2vni(domain, attachment)
                case _:
                    pass

    async def remove(self, domain: VRFDomain) -> None:
        for attachment in domain.attachments:
            match attachment.kind:
                case 'l2vni':
                    await self.remove_l2vni(domain, attachment)
                case _:
                    pass

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
        host_link: int = 0
        host_src: str = ''
        host_ifname: str = ''

        async with AsyncIPRoute() as ipr:
            logging.info('trying to calculate host_if')
            default_route = await ipr.route('get', dst='1.1.1.1')
            host_link = default_route[0].get('oif')
            host_src = default_route[0].get('prefsrc') or '127.0.0.1'
            host_ifname = (await ipr.link('get', index=host_link))[0].get(
                'ifname'
            )
            logging.info(
                f'host discovery: {host_link}:{host_ifname}:{host_src}'
            )

        domain = VRFDomain(
            name=f'vrf-{default_vrf}',
            vrf=default_vrf,
            table=default_vrf,
            prefix=default_prefix,
            prefixlen=default_prefixlen,
            ipblocklen=(
                int(self.config['default']['ipblocklen'])
                if self.config['default'].get('ipblocklen') is not None
                else None
            ),
            attachments=[
                VRFAttachment(
                    kind='l2vni', vni=default_vrf, dev=host_ifname, port=4789
                )
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
