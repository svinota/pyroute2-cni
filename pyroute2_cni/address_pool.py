import asyncio
import logging
import random
import re
from configparser import ConfigParser
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, cast

from kubernetes.client.exceptions import ApiException
from pyroute2 import AsyncIPRoute

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config  # type: ignore[attr-defined]
from pyroute2_cni.crds.vrf_domain import parse_vrf_domain

IPBLOCK_GROUP = 'ipam.pyroute2.org'
IPBLOCK_VERSION = 'v1alpha1'
IPBLOCK_PLURAL = 'ipblocks'
IPBLOCK_NAME_RE = re.compile(r'^vrf-\d+-\d+-\d+-\d+-\d+-\d+$')


class IPBlockConflict(RuntimeError):
    pass


class IPBlockStaleResource(RuntimeError):
    pass


@dataclass(frozen=True)
class IPBlock:
    name: str
    node_name: str
    vrf_table: int
    cidr: IPv4Network
    allocations: dict[str, str]
    allocated: int
    capacity: int
    resource_version: str
    creation_timestamp: str


@dataclass
class AddressAllocation:
    address: IPv4Address
    gateway: IPv4Address


@dataclass(frozen=True)
class RunningPod:
    namespace: str
    name: str
    uid: str
    ip: str


class AddressPool:
    def __init__(self, node_name: str, config: ConfigParser) -> None:
        self.node_name = node_name
        self.config = config
        self._alloc_lock = asyncio.Lock()
        self.block_prefixlen = int(
            self.config['default'].get(
                'ipblocklen', self.config['default']['prefixlen']
            )
        )
        self.k8s_custom_api, self.k8s_v1 = self._load_k8s_clients()

    def _load_k8s_clients(
        self,
    ) -> tuple[k8s_client.CustomObjectsApi, k8s_client.CoreV1Api]:
        try:
            k8s_config.load_incluster_config()  # type: ignore[attr-defined]
        except Exception:
            k8s_config.load_kube_config()  # type: ignore[attr-defined]
        return (k8s_client.CustomObjectsApi(), k8s_client.CoreV1Api())

    def _domain_defaults(self) -> int:
        return int(self.config['default']['vrf'])

    def _block_name(self, cidr: IPv4Network, vrf_table: int) -> str:
        safe_cidr = str(cidr.network_address).replace('.', '-')
        return f'vrf-{vrf_table}-{safe_cidr}-{cidr.prefixlen}'

    def _block_capacity(self, cidr: IPv4Network) -> int:
        return max(cidr.num_addresses - 2, 0)

    def _raw_block_items(self) -> list[dict[str, Any]]:
        response = self.k8s_custom_api.list_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL
        )
        result: list[dict[str, Any]] = []
        for item in response.get('items', []):
            metadata = item.get('metadata') or {}
            name = metadata.get('name') or item.get('name') or ''
            if not IPBLOCK_NAME_RE.match(name):
                logging.warning('skipping legacy IPBlock %s', name)
                continue
            result.append(item)
        return result

    def _parse_block(self, item: dict[str, Any]) -> IPBlock:
        metadata = item.get('metadata') or {}
        spec = item.get('spec') or {}
        status = item.get('status') or {}
        resource_version = metadata.get('resourceVersion') or ''
        cidr = spec.get('cidr')
        if not cidr:
            raise KeyError('cidr')
        block = IPv4Network(cidr)
        allocations = status.get('allocations') or {}
        name = metadata.get('name') or item.get('name')
        if not name:
            raise KeyError('name')
        allocated = status.get('allocated')
        if allocated is None:
            allocated = len(allocations)
        vrf_table = spec.get('vrfTable') or self.config['default']['vrf']
        return IPBlock(
            name=name,
            node_name=spec.get('nodeName') or '',
            vrf_table=int(vrf_table),
            cidr=block,
            allocations=allocations,
            allocated=int(allocated),
            capacity=int(
                status.get('capacity') or self._block_capacity(block)
            ),
            resource_version=resource_version,
            creation_timestamp=metadata.get('creationTimestamp', ''),
        )

    def _list_vrf_ipblocks(
        self, network: IPv4Network, vrf_table: int
    ) -> list[IPBlock]:
        '''
        List normalized IPBlocks for this domain within `network`.

        Claims are node-scoped and cluster-visible.
        '''
        result: list[IPBlock] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block.vrf_table != vrf_table:
                continue
            if block.cidr.subnet_of(network):
                result.append(block)
        result.sort(
            key=lambda x: (int(x.cidr.network_address), x.cidr.prefixlen)
        )
        return result

    def _own_block_items(
        self, network: IPv4Network, vrf_table: int
    ) -> list[IPBlock]:
        return [
            item
            for item in self._list_vrf_ipblocks(network, vrf_table)
            if item.node_name == self.node_name
        ]

    def _all_block_cidrs(
        self, network: IPv4Network, vrf_table: int
    ) -> set[IPv4Network]:
        response = self.k8s_custom_api.list_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL
        )
        cidrs: set[IPv4Network] = set()
        for item in response.get('items', []):
            spec = item.get('spec') or {}
            cidr = spec.get('cidr')
            if not cidr:
                continue
            item_vrf = int(spec.get('vrfTable', self._domain_defaults()))
            if item_vrf != vrf_table:
                continue
            block = IPv4Network(cidr)
            if block.subnet_of(network):
                cidrs.add(block)
        return cidrs

    def block_cidrs(
        self, network: IPv4Network, vrf_table: int
    ) -> set[IPv4Network]:
        return self._all_block_cidrs(network, vrf_table)

    def _node_block_items(self) -> list[IPBlock]:
        result: list[IPBlock] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block.node_name != self.node_name:
                continue
            result.append(block)
        return result

    def _node_used_ips(self, network: IPv4Network, vrf_table: int) -> set[str]:
        used: set[str] = set()
        for pod in self._list_allocated_pods():
            used.add(pod.ip)
        return used

    def _find_free_ip_excluding(
        self,
        cidr: IPv4Network,
        allocations: dict[str, str],
        excluded: set[str],
    ) -> IPv4Address:
        for ip in cidr.hosts():
            ip_str = ip.compressed
            if ip_str in allocations:
                continue
            if ip_str in excluded:
                logging.warning(f'consistency: {ip_str} not in the IPBlock')
                continue
            return ip
        raise KeyError('no free addresses found')

    def _delete_block(self, name: str) -> None:
        self.k8s_custom_api.delete_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, name
        )

    async def _cleanup_allocations(self, allocations: dict[str, str]) -> None:
        async with AsyncIPRoute() as ipr:
            for record in allocations:
                dump = [
                    x async for x in await ipr.addr('dump', address=record)
                ]
                if len(dump) != 1:
                    logging.warning(
                        f'consistency: found multiple addresses for {record}'
                    )
                    continue
                for address in dump:
                    await ipr.ensure(
                        ipr.addr,
                        present=False,
                        index=address.get('index'),
                        address=address.get('address'),
                        prefixlen=address.get('prefixlen'),
                    )

    def _list_allocated_pods(self) -> list[RunningPod]:
        response = self.k8s_v1.list_pod_for_all_namespaces(
            field_selector=f'spec.nodeName={self.node_name}'
        )
        result: list[RunningPod] = []
        for item in response.items:
            status = item.status
            if status is None:
                continue
            pod_ip = getattr(status, 'pod_ip', None)
            if not pod_ip:
                continue
            metadata = item.metadata
            if metadata is None:
                continue
            if item.spec is not None and item.spec.host_network:
                continue
            if not metadata.uid:
                continue
            result.append(
                RunningPod(
                    namespace=metadata.namespace or '',
                    name=metadata.name or '',
                    uid=metadata.uid,
                    ip=pod_ip,
                )
            )
        return result

    async def gc_empty_blocks(self) -> int:
        logging.debug('Starting IPBlock GC')
        limit: int = 1
        keep: int = 1
        live_domains: set[int] = set()
        response = self.k8s_custom_api.list_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
        )
        for item in response.get('items', []):
            domain = parse_vrf_domain(item)
            live_domains.add(domain.vrf)

        orphaned_blocks: list[IPBlock] = []
        empty_blocks_by_domain: dict[int, list[IPBlock]] = {}
        for item in self._node_block_items():
            vrf = item.vrf_table
            if vrf not in live_domains:
                orphaned_blocks.append(item)
                continue
            if len(item.allocations) != item.allocated:
                logging.warning(
                    f'consistency: IPBlock {item.name} has unexpected '
                    f'counter: allocated={item.allocated}'
                )
                continue
            if item.allocated > 1:
                continue
            if set(item.allocations.values()) != {'gateway'}:
                logging.warning(
                    f'consistency: IPBlock {item.name} has unexpected '
                    f'allocations: allocations={item.allocations}'
                )
                continue
            empty_blocks_by_domain.setdefault(vrf, []).append(item)

        for block in orphaned_blocks:
            logging.info(f'Deleting orphaned IPBlock {block.name}')
            try:
                await self._cleanup_allocations(block.allocations)
                self._delete_block(block.name)
            except ApiException as err:
                logging.warning(
                    'failed to delete orphaned IPBlock %s: %s', block.name, err
                )
        empty_blocks: list[IPBlock] = []
        for blocks in empty_blocks_by_domain.values():
            blocks.sort(key=lambda x: x.creation_timestamp)
            if len(blocks) > keep:
                empty_blocks.extend(blocks[: len(blocks) - keep])
        empty_blocks.sort(key=lambda x: x.creation_timestamp)
        deletions = 0
        while empty_blocks and deletions < limit:
            empty_block: IPBlock = empty_blocks.pop(0)
            logging.info(f'Deleting IPBlock {empty_block.name}')
            try:
                await self._cleanup_allocations(empty_block.allocations)
                self._delete_block(empty_block.name)
                deletions += 1
            except ApiException as err:
                logging.warning(
                    'failed to delete empty IPBlock %s: %s',
                    empty_block.name,
                    err,
                )
                break
        return deletions

    def _next_free_block(
        self, network: IPv4Network, ipblocklen: int, vrf_table: int
    ) -> IPv4Network:
        used = self._all_block_cidrs(network, vrf_table)
        block_prefixlen = (
            ipblocklen if ipblocklen is not None else self.block_prefixlen
        )
        for block in network.subnets(new_prefix=block_prefixlen):
            if block not in used:
                return block
        raise RuntimeError(f'no available IPBlocks in {network}')

    def _create_block(
        self, network: IPv4Network, cidr: IPv4Network, vrf_table: int
    ) -> IPBlock:
        body = {
            'apiVersion': f'{IPBLOCK_GROUP}/{IPBLOCK_VERSION}',
            'kind': 'IPBlock',
            'metadata': {
                'name': self._block_name(cidr, vrf_table),
                'labels': {
                    'pyroute2.org/node': self.node_name,
                    'pyroute2.org/vrf': str(vrf_table),
                },
            },
            'spec': {
                'cidr': cidr.compressed,
                'nodeName': self.node_name,
                'vrfTable': vrf_table,
            },
        }
        try:
            created = cast(
                dict[str, Any],
                self.k8s_custom_api.create_cluster_custom_object(
                    IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, body
                ),
            )
            return self._parse_block(created)
        except ApiException as err:
            if err.status == 409:
                for item in self._list_vrf_ipblocks(network, vrf_table):
                    if item.cidr == cidr:
                        if item.node_name != self.node_name:
                            logging.info(
                                f'reject foreign block create fallback '
                                f'block=i{item} cidr={cidr}'
                            )
                            raise IPBlockConflict(
                                f'IPBlock {cidr} already exists for another '
                                f'node'
                            )
                        return item
                raise IPBlockConflict(
                    f'IPBlock {cidr} already exists for {vrf_table}'
                )
            raise

    def _patch_block_status(
        self, item: IPBlock, allocations: dict[str, str]
    ) -> None:
        name = item.name
        cidr = item.cidr
        body = {
            'apiVersion': f'{IPBLOCK_GROUP}/{IPBLOCK_VERSION}',
            'kind': 'IPBlock',
            'metadata': {
                'name': name,
                'resourceVersion': item.resource_version,
            },
            'spec': {
                'cidr': cidr.compressed,
                'nodeName': self.node_name,
                'vrfTable': item.vrf_table,
            },
            'status': {
                'allocated': len(allocations),
                'capacity': self._block_capacity(cidr),
                'allocations': allocations,
            },
        }
        logging.info(f'Patching: {allocations}')
        try:
            self.k8s_custom_api.replace_cluster_custom_object_status(
                IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, name, body
            )
        except ApiException as err:
            if err.status == 409:
                raise IPBlockStaleResource(f'IPBlock {name} is stale') from err
            raise

    def _find_free_ip(
        self, cidr: IPv4Network, allocations: dict[str, str]
    ) -> IPv4Address:
        for ip in cidr.hosts():
            if ip.compressed not in allocations:
                return ip
        raise KeyError('no free addresses found')

    def _has_free_ip(
        self, cidr: IPv4Network, allocations: dict[str, str]
    ) -> bool:
        try:
            self._find_free_ip(cidr, allocations)
        except KeyError:
            return False
        except Exception:
            raise
        return True

    def _block_for_ip(
        self,
        network: IPv4Network,
        ip: IPv4Address,
        ipblocklen: int | None = None,
    ) -> IPv4Network:
        block_prefixlen = (
            ipblocklen if ipblocklen is not None else self.block_prefixlen
        )
        block = IPv4Network(f'{ip}/{block_prefixlen}', strict=False)
        if not block.subnet_of(network):
            raise ValueError(f'{ip} is outside of {network}')
        return block

    def _select_or_create_block(
        self, network: IPv4Network, ipblocklen: int, vrf_table: int
    ) -> IPBlock:
        existing_blocks = self._own_block_items(network, vrf_table)
        logging.info(f'select block vrf={vrf_table} network={network}')
        for item in existing_blocks:
            if self._has_free_ip(item.cidr, item.allocations):
                logging.info(f'selected existing block name={item.name}')
                return item

        next_block = self._next_free_block(network, ipblocklen, vrf_table)
        logging.info(f'creating new block name {next_block}')
        return self._create_block(network, next_block, vrf_table)

    async def _acquire_block(
        self,
        network: IPv4Network,
        ipblocklen: int,
        vrf_table: int,
        max_attempts: int = 5,
    ) -> IPBlock:
        for attempt in range(max_attempts):
            try:
                logging.info(f'acquire block attempt={attempt}')
                return self._select_or_create_block(
                    network, ipblocklen, vrf_table
                )
            except IPBlockConflict:
                logging.info(
                    f'acquire block conflict network={network} '
                    f'ipblocklen={ipblocklen} vrf_table={vrf_table}'
                )
                await asyncio.sleep(0.1 + random.random() * 0.4)
        raise RuntimeError('unable to acquire IPBlock')

    async def release(self, pod_uid: str) -> None:
        logging.info(f'Starting release pod_uid={pod_uid}')
        async with self._alloc_lock:
            for item in self._node_block_items():
                allocations = dict(item.allocations)
                for ip, ref in tuple(allocations.items()):
                    if ref != pod_uid:
                        continue
                    allocations.pop(ip, None)
                    self._patch_block_status(item, allocations)
                    logging.info(f'Done release pod_uid={pod_uid}')
                    return
            raise KeyError('address not allocated')

    async def allocate(
        self,
        network: IPv4Network,
        ipblocklen: int,
        vrf_table: int,
        pod_uid: str = '',
        is_gateway: bool = False,
    ) -> AddressAllocation:
        logging.info(f'Starting allocation pod_uid={pod_uid}')
        async with self._alloc_lock:
            gateway: IPv4Address
            block = await self._acquire_block(network, ipblocklen, vrf_table)
            allocations = dict(block.allocations)
            reverse_lookup = dict([(x[1], x[0]) for x in allocations.items()])
            used_ips = self._node_used_ips(network, vrf_table)
            if 'gateway' in reverse_lookup:
                gateway = IPv4Address(reverse_lookup['gateway'])
            else:
                gateway = self._find_free_ip_excluding(
                    block.cidr, allocations, used_ips
                )
            allocations[gateway.compressed] = 'gateway'
            used_ips.add(gateway.compressed)
            # gateway is ALWAYS not None with prefixlen < 32
            logging.info(f'allocate: acquired gateway={gateway}')
            if is_gateway:
                ip = IPv4Address('0.0.0.0')
                logging.info(f'Done allocation for gateway={gateway}')
            else:
                if pod_uid in reverse_lookup:
                    ip = IPv4Address(reverse_lookup[pod_uid])
                else:
                    ip = self._find_free_ip_excluding(
                        block.cidr, allocations, used_ips
                    )
                # ip is always not None with prefixlen < 32
                logging.info(f'allocate: acquired ip={ip}')
                allocations[ip.compressed] = pod_uid
                logging.info(
                    f'Done allocation pod_uid={pod_uid} '
                    f'ip={ip} gateway={gateway}'
                )
            self._patch_block_status(block, allocations)
            logging.info(f'Patched block {block.name}')
            return AddressAllocation(ip, gateway)
