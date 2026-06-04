import asyncio
import logging
import random
import re
import struct
from configparser import ConfigParser
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, cast

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config  # type: ignore[attr-defined]

from .vrf_domain import parse_vrf_domain

IPBLOCK_GROUP = 'ipam.pyroute2.org'
IPBLOCK_VERSION = 'v1alpha1'
IPBLOCK_PLURAL = 'ipblocks'
IPBLOCK_NAME_RE = re.compile(r'^vrf-\d+-\d+-\d+-\d+-\d+-\d+$')


class IPBlockConflict(RuntimeError):
    pass


class IPBlockStaleResource(RuntimeError):
    pass


@dataclass
class AddressMetadata:
    vrf_table: int
    node: str
    pod_uid: str
    is_gateway: bool
    network: str
    address: str


class AddressPool:
    def __init__(self, node_name: str, config: ConfigParser) -> None:
        self.node_name = node_name
        self.config = config
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

    def _resolve_domain(self, vrf_table: int | None = None) -> int:
        default_vrf = self._domain_defaults()
        return default_vrf if vrf_table is None else int(vrf_table)

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

    def _parse_block(self, item: dict[str, Any]) -> dict[str, Any]:
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
        vrf_table = self._resolve_domain(spec.get('vrfTable'))
        return {
            'name': name,
            'node_name': spec.get('nodeName') or '',
            'vrf_table': vrf_table,
            'cidr': block,
            'allocations': allocations,
            'allocated': int(allocated),
            'capacity': int(
                status.get('capacity') or self._block_capacity(block)
            ),
            'resource_version': resource_version,
            'creation_timestamp': metadata.get('creationTimestamp', ''),
        }

    def _list_vrf_ipblocks(
        self, network: IPv4Network, vrf_table: int
    ) -> list[dict[str, Any]]:
        '''
        List normalized IPBlocks for this domain within `network`.

        Claims are node-scoped and cluster-visible.
        '''
        result: list[dict[str, Any]] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block['vrf_table'] != vrf_table:
                continue
            if block['cidr'].subnet_of(network):
                result.append(block)
        result.sort(
            key=lambda x: (int(x['cidr'].network_address), x['cidr'].prefixlen)
        )
        return result

    def _own_block_items(
        self, network: IPv4Network, vrf_table: int
    ) -> list[dict[str, Any]]:
        return [
            item
            for item in self._list_vrf_ipblocks(network, vrf_table)
            if item['node_name'] == self.node_name
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

    def _node_block_items(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block['node_name'] != self.node_name:
                continue
            result.append(block)
        return result

    async def prune_stale_allocations(
        self,
        network: IPv4Network,
        vrf_table: int,
        live_pod_ips: dict[str, str],
        gateway_ip: str | None = None,
    ) -> int:
        removed = 0
        logging.info('prune allocations')
        for item in self._node_block_items():
            logging.info(f'Block item {item}')
            if item['vrf_table'] != vrf_table or not item['cidr'].subnet_of(
                network
            ):
                continue
            if item['node_name'] != self.node_name:
                logging.warning(
                    'skipping foreign IPBlock %s owned by %s during prune',
                    item['name'],
                    item['node_name'],
                )
                continue
            logging.info('Process allocations')
            allocations = dict(item['allocations'])
            for ip, ref in tuple(allocations.items()):
                keep = (
                    ref == 'gateway'
                    and gateway_ip is not None
                    and ip == gateway_ip
                ) or (live_pod_ips.get(ref) == ip)
                logging.info(f'>>> Block ip: {ip} : {ref} : {keep}')
                if keep:
                    continue
                allocations.pop(ip, None)
                removed += 1
            if allocations != item['allocations']:
                self._patch_block_status(item, allocations)
        return removed

    async def restore_live_allocations(
        self,
        network: IPv4Network,
        vrf_table: int,
        live_pod_ips: dict[str, str],
    ) -> int:
        restored = 0
        for item in self._node_block_items():
            if item['vrf_table'] != vrf_table or not item['cidr'].subnet_of(
                network
            ):
                continue
            if item['node_name'] != self.node_name:
                logging.warning(
                    'skipping foreign IPBlock %s owned by %s during restore',
                    item['name'],
                    item['node_name'],
                )
                continue
            allocations = dict(item['allocations'])
            for pod_uid, pod_ip in live_pod_ips.items():
                if pod_ip in allocations:
                    continue
                try:
                    if (
                        self._block_for_ip(network, IPv4Address(pod_ip))
                        != item['cidr']
                    ):
                        continue
                except ValueError:
                    continue
                allocations[pod_ip] = pod_uid
                restored += 1
            if allocations != item['allocations']:
                self._patch_block_status(item, allocations)
        return restored

    def _delete_block(self, name: str) -> None:
        self.k8s_custom_api.delete_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, name
        )

    async def gc_empty_blocks(self, limit: int = 1, keep: int = 0) -> int:
        logging.info('Starting IPBlock GC')
        live_domains: set[int] = set()
        response = self.k8s_custom_api.list_cluster_custom_object(
            'cni.pyroute2.org', 'v1alpha1', 'vrfdomains'
        )
        for item in response.get('items', []):
            domain = parse_vrf_domain(item)
            live_domains.add(domain.vrf)

        orphaned_blocks: list[dict[str, Any]] = []
        empty_blocks_by_domain: dict[int, list[dict[str, Any]]] = {}
        for item in self._node_block_items():
            domain = item['vrf_table']
            if domain not in live_domains:
                orphaned_blocks.append(item)
                continue
            if item['allocated'] != 0:
                continue
            empty_blocks_by_domain.setdefault(domain, []).append(item)

        for block in orphaned_blocks:
            logging.info(f'Deleting orphaned IPBlock {block["name"]}')
            try:
                self._delete_block(block['name'])
            except ApiException as err:
                logging.warning(
                    'failed to delete orphaned IPBlock %s: %s',
                    block['name'],
                    err,
                )
        empty_blocks: list[dict[str, Any]] = []
        for blocks in empty_blocks_by_domain.values():
            blocks.sort(key=lambda x: x['creation_timestamp'])
            if len(blocks) > keep:
                empty_blocks.extend(blocks[: len(blocks) - keep])
        empty_blocks.sort(key=lambda x: x['creation_timestamp'])
        deletions = 0
        while empty_blocks and deletions < limit:
            block = empty_blocks.pop(0)
            logging.info(f'Deleting IPBlock {block["name"]}')
            try:
                self._delete_block(block['name'])
                deletions += 1
            except ApiException as err:
                logging.warning(
                    'failed to delete empty IPBlock %s: %s', block['name'], err
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
    ) -> dict[str, Any]:
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
                    if item['cidr'] == cidr:
                        if item['node_name'] != self.node_name:
                            logging.info(
                                'reject foreign block create fallback '
                                'node=%s block=%s owner=%s cidr=%s',
                                self.node_name,
                                item['name'],
                                item['node_name'],
                                item['cidr'],
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

    def _get_block_by_cidr(
        self, network: IPv4Network, cidr: IPv4Network, vrf_table: int
    ) -> dict[str, Any]:
        for item in self._list_vrf_ipblocks(network, vrf_table):
            if item['cidr'] == cidr:
                return item
        raise KeyError(f'IPBlock {cidr} not found')

    def _patch_block_status(
        self, item: dict[str, Any], allocations: dict[str, str]
    ) -> None:
        name = item['name']
        cidr = item['cidr']
        body = {
            'apiVersion': f'{IPBLOCK_GROUP}/{IPBLOCK_VERSION}',
            'kind': 'IPBlock',
            'metadata': {
                'name': name,
                'resourceVersion': item['resource_version'],
            },
            'spec': {
                'cidr': cidr.compressed,
                'nodeName': self.node_name,
                'vrfTable': item['vrf_table'],
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
    ) -> IPv4Address | None:
        for ip in cidr.hosts():
            if ip.compressed not in allocations:
                return ip
        return None

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

    def _ensure_block_for_ip(
        self,
        network: IPv4Network,
        ip: IPv4Address,
        vrf_table: int,
        ipblocklen: int | None = None,
    ) -> dict[str, Any]:
        block_cidr = self._block_for_ip(network, ip, ipblocklen=ipblocklen)
        for item in self._list_vrf_ipblocks(network, vrf_table):
            if item['cidr'] == block_cidr:
                if item['node_name'] != self.node_name:
                    logging.info(
                        'reject foreign block by ip node=%s block=%s '
                        'owner=%s cidr=%s',
                        self.node_name,
                        item['name'],
                        item['node_name'],
                        item['cidr'],
                    )
                    raise IPBlockConflict(
                        f'IPBlock {block_cidr} already exists for another node'
                    )
                return item
        return self._create_block(network, block_cidr, vrf_table)

    def _select_block(
        self,
        network: IPv4Network,
        ipblocklen: int,
        vrf_table: int,
        ip: IPv4Address | None = None,
    ) -> dict[str, Any]:
        existing_blocks = self._own_block_items(network, vrf_table)
        logging.info(
            'select block node=%s vrf=%s network=%s ip=%s own_blocks=%s',
            self.node_name,
            vrf_table,
            network,
            ip,
            [f"{item['name']}:{item['cidr']}" for item in existing_blocks],
        )
        if ip is not None:
            block_cidr = self._block_for_ip(network, ip, ipblocklen=ipblocklen)
            logging.info(
                'select block by ip node=%s vrf=%s cidr=%s',
                self.node_name,
                vrf_table,
                block_cidr,
            )
            for item in existing_blocks:
                if item['cidr'] == block_cidr:
                    logging.info(
                        'reusing own block node=%s name=%s cidr=%s',
                        self.node_name,
                        item['name'],
                        item['cidr'],
                    )
                    return item
            all_blocks = self._list_vrf_ipblocks(network, vrf_table)
            logging.info(
                'block by ip not owned node=%s cidr=%s all_blocks=%s',
                self.node_name,
                block_cidr,
                [
                    f"{item['name']}:{item['node_name']}:{item['cidr']}"
                    for item in all_blocks
                ],
            )
            if any(item['cidr'] == block_cidr for item in all_blocks):
                raise IPBlockConflict(
                    f'IPBlock {block_cidr} already exists for another node'
                )
            logging.info(
                'creating block by ip node=%s cidr=%s vrf=%s',
                self.node_name,
                block_cidr,
                vrf_table,
            )
            return self._create_block(network, block_cidr, vrf_table)

        for item in existing_blocks:
            free_ip = self._find_free_ip(item['cidr'], item['allocations'])
            logging.info(
                'inspect own block node=%s name=%s cidr=%s free_ip=%s '
                'allocations=%s',
                self.node_name,
                item['name'],
                item['cidr'],
                free_ip,
                item['allocations'],
            )
            if free_ip is not None:
                logging.info(
                    'selected existing block node=%s name=%s cidr=%s',
                    self.node_name,
                    item['name'],
                    item['cidr'],
                )
                return item

        next_block = self._next_free_block(network, ipblocklen, vrf_table)
        logging.info(
            'creating new block node=%s vrf=%s cidr=%s',
            self.node_name,
            vrf_table,
            next_block,
        )
        return self._create_block(network, next_block, vrf_table)

    async def _acquire_block(
        self,
        network: IPv4Network,
        ipblocklen: int,
        vrf_table: int,
        ip: IPv4Address | None = None,
        max_attempts: int = 5,
    ) -> dict[str, Any]:
        if ip is not None:
            logging.info(
                'acquire block direct node=%s vrf=%s ip=%s',
                self.node_name,
                vrf_table,
                ip,
            )
            return self._select_block(network, ipblocklen, vrf_table, ip)

        for attempt in range(max_attempts):
            try:
                logging.info(
                    'acquire block attempt=%s node=%s vrf=%s',
                    attempt + 1,
                    self.node_name,
                    vrf_table,
                )
                return self._select_block(network, ipblocklen, vrf_table, ip)
            except IPBlockConflict:
                logging.info(
                    'acquire block conflict attempt=%s node=%s vrf=%s',
                    attempt + 1,
                    self.node_name,
                    vrf_table,
                )
                if attempt + 1 >= max_attempts:
                    raise
                await asyncio.sleep(0.1 + random.random() * 0.4)
                continue
        raise RuntimeError('unable to acquire IPBlock')

    def inet_aton(self, network: IPv4Network, address: str) -> int:
        return (
            struct.unpack('>I', IPv4Address(address).packed)[0]
            & struct.unpack('>I', network.hostmask.packed)[0]
        )

    def inet_ntoa(self, network: str, address: int) -> str:
        return IPv4Network(network)[address].compressed

    async def release(self, pod_uid: str) -> AddressMetadata:
        for item in self._node_block_items():
            allocations = dict(item['allocations'])
            for ip, ref in tuple(allocations.items()):
                if ref != pod_uid:
                    continue
                metadata = AddressMetadata(
                    item['vrf_table'],
                    self.node_name,
                    pod_uid,
                    False,
                    item['cidr'].compressed,
                    ip,
                )
                allocations.pop(ip, None)
                self._patch_block_status(item, allocations)
                return metadata
        raise KeyError('address not allocated')

    async def allocate(
        self,
        network: IPv4Network,
        ipblocklen: int,
        vrf_table: int,
        is_gateway: bool = False,
        pod_uid: str = '',
        address: int = -1,
    ) -> str:
        vrf_table = self._resolve_domain(vrf_table)
        ref = pod_uid or ('gateway' if is_gateway else '')
        ip = IPv4Address(network[address]) if address >= 0 else None
        logging.info(
            'allocate start node=%s vrf=%s network=%s is_gateway=%s '
            'pod_uid=%s address=%s ref=%s ip=%s',
            self.node_name,
            vrf_table,
            network,
            is_gateway,
            pod_uid,
            address,
            ref,
            ip,
        )
        block = await self._acquire_block(network, ipblocklen, vrf_table, ip)
        allocations = dict(block['allocations'])
        logging.info(
            'allocate selected block node=%s block=%s owner=%s cidr=%s '
            'allocations=%s',
            self.node_name,
            block['name'],
            block['node_name'],
            block['cidr'],
            allocations,
        )

        if ip is None:
            ip = self._find_free_ip(block['cidr'], allocations)
            logging.info(
                'allocate picked free ip node=%s block=%s ip=%s '
                'allocations=%s',
                self.node_name,
                block['name'],
                ip,
                allocations,
            )
            if ip is None:
                max_attempts = 5
                for attempt in range(max_attempts):
                    try:
                        logging.info(
                            'allocate fallback create attempt=%s '
                            'node=%s vrf=%s',
                            attempt + 1,
                            self.node_name,
                            vrf_table,
                        )
                        block = self._create_block(
                            network,
                            self._next_free_block(
                                network, ipblocklen, vrf_table
                            ),
                            vrf_table,
                        )
                        allocations = dict(block['allocations'])
                        ip = self._find_free_ip(block['cidr'], allocations)
                        logging.info(
                            'allocate fallback block node=%s block=%s ip=%s '
                            'allocations=%s',
                            self.node_name,
                            block['name'],
                            ip,
                            allocations,
                        )
                        if ip is None:
                            raise RuntimeError(
                                f'no free IPs in {block["cidr"]}'
                            )
                        break
                    except IPBlockConflict:
                        if attempt + 1 >= max_attempts:
                            raise
                        await asyncio.sleep(0.1 + random.random() * 0.4)
                        continue

        if ip is None:
            raise RuntimeError('no free IPs')

        if ip.compressed in allocations:
            existing = allocations[ip.compressed]
            logging.info(
                'allocate found existing ip node=%s block=%s ip=%s '
                'existing=%s ref=%s',
                self.node_name,
                block['name'],
                ip,
                existing,
                ref,
            )
            if existing and existing != ref:
                raise RuntimeError(f'IP {ip} already allocated to {existing}')
            return self.inet_ntoa(
                network.compressed, self.inet_aton(network, ip.compressed)
            )

        allocations[ip.compressed] = ref
        logging.info(
            'allocate patching node=%s block=%s ip=%s ref=%s allocations=%s',
            self.node_name,
            block['name'],
            ip,
            ref,
            allocations,
        )
        try:
            self._patch_block_status(block, allocations)
        except IPBlockStaleResource:
            logging.info(
                'allocate stale resource retry node=%s block=%s ip=%s',
                self.node_name,
                block['name'],
                ip,
            )
            return await self.restore(
                network=network,
                ipblocklen=ipblocklen,
                vrf_table=vrf_table,
                is_gateway=is_gateway,
                pod_uid=pod_uid,
                address=address,
            )
        return self.inet_ntoa(
            network.compressed, self.inet_aton(network, ip.compressed)
        )

    async def restore(
        self,
        network: IPv4Network,
        ipblocklen: int,
        vrf_table: int | None = None,
        is_gateway: bool = False,
        pod_uid: str = '',
        address: int = -1,
    ) -> str:
        vrf_table = self._resolve_domain(vrf_table)
        ref = pod_uid or ('gateway' if is_gateway else '')
        ip = IPv4Address(network[address]) if address >= 0 else None
        block = await self._acquire_block(network, ipblocklen, vrf_table, ip)
        allocations = dict(block['allocations'])

        if ip is None:
            ip = self._find_free_ip(block['cidr'], allocations)
            if ip is None:
                raise RuntimeError('no free IPs')

        if ip.compressed in allocations:
            existing = allocations[ip.compressed]
            if existing and existing != ref:
                logging.warning(
                    'reconciling stale allocation for %s: %s -> %s',
                    ip,
                    existing,
                    ref,
                )
                allocations[ip.compressed] = ref
                try:
                    self._patch_block_status(block, allocations)
                except IPBlockStaleResource:
                    return await self.restore(
                        network=network,
                        ipblocklen=ipblocklen,
                        vrf_table=vrf_table,
                        is_gateway=is_gateway,
                        pod_uid=pod_uid,
                        address=address,
                    )
            return self.inet_ntoa(
                network.compressed, self.inet_aton(network, ip.compressed)
            )

        allocations[ip.compressed] = ref
        try:
            self._patch_block_status(block, allocations)
        except IPBlockStaleResource:
            return await self.restore(
                network=network,
                ipblocklen=ipblocklen,
                vrf_table=vrf_table,
                is_gateway=is_gateway,
                pod_uid=pod_uid,
                address=address,
            )
        return self.inet_ntoa(
            network.compressed, self.inet_aton(network, ip.compressed)
        )
