import logging
import struct
from configparser import ConfigParser
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network
from typing import Any, cast

from kubernetes.client.exceptions import ApiException

from kubernetes import client as k8s_client
from kubernetes import config as k8s_config  # type: ignore[attr-defined]

IPBLOCK_GROUP = 'ipam.pyroute2.org'
IPBLOCK_VERSION = 'v1alpha1'
IPBLOCK_PLURAL = 'ipblocks'


@dataclass
class AddressMetadata:
    vrf_table: int
    vxlan_id: int
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
            k8s_config.load_incluster_config()
        except Exception:
            k8s_config.load_kube_config()
        return (k8s_client.CustomObjectsApi(), k8s_client.CoreV1Api())

    def _domain_defaults(self) -> tuple[int, int]:
        return (
            int(self.config['default'].get('vrf', 0)),
            int(self.config['default'].get('vxlan', 0)),
        )

    def _resolve_domain(
        self, vrf_table: int | None = None, vxlan_id: int | None = None
    ) -> tuple[int, int]:
        default_vrf, default_vxlan = self._domain_defaults()
        return (
            default_vrf if vrf_table is None else int(vrf_table),
            default_vxlan if vxlan_id is None else int(vxlan_id),
        )

    def _block_name(
        self, cidr: IPv4Network, vrf_table: int, vxlan_id: int
    ) -> str:
        safe_node = ''.join(
            x if x.isalnum() or x == '-' else '-'
            for x in self.node_name.lower()
        )
        safe_cidr = str(cidr.network_address).replace('.', '-')
        return (
            f'{safe_node}-vrf{vrf_table}-vx{vxlan_id}-'
            f'{safe_cidr}-{cidr.prefixlen}'
        )

    def _block_capacity(self, cidr: IPv4Network) -> int:
        return max(cidr.num_addresses - 2, 0)

    def _raw_block_items(self) -> list[dict[str, Any]]:
        response = self.k8s_custom_api.list_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL
        )
        return response.get('items', [])

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
        vrf_table, vxlan_id = self._resolve_domain(
            spec.get('vrfTable'), spec.get('vxlanId')
        )
        return {
            'name': name,
            'node_name': spec.get('nodeName') or '',
            'vrf_table': vrf_table,
            'vxlan_id': vxlan_id,
            'cidr': block,
            'allocations': allocations,
            'allocated': int(allocated),
            'capacity': int(
                status.get('capacity') or self._block_capacity(block)
            ),
            'resource_version': resource_version,
            'creation_timestamp': metadata.get('creationTimestamp', ''),
        }

    def _block_items(
        self, network: IPv4Network, vrf_table: int, vxlan_id: int
    ) -> list[dict[str, Any]]:
        '''
        List normalized IPBlocks for this node and domain within `network`.

        Only blocks owned by this node, matching `vrf_table` / `vxlan_id`,
        and contained in `network` are returned.
        '''
        result: list[dict[str, Any]] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block['node_name'] != self.node_name:
                continue
            if (
                block['vrf_table'] != vrf_table
                or block['vxlan_id'] != vxlan_id
            ):
                continue
            if block['cidr'].subnet_of(network):
                result.append(block)
        result.sort(
            key=lambda x: (int(x['cidr'].network_address), x['cidr'].prefixlen)
        )
        return result

    def _all_block_cidrs(
        self, network: IPv4Network, vrf_table: int, vxlan_id: int
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
            item_vrf = int(spec.get('vrfTable', self._domain_defaults()[0]))
            item_vxlan = int(spec.get('vxlanId', self._domain_defaults()[1]))
            if item_vrf != vrf_table or item_vxlan != vxlan_id:
                continue
            block = IPv4Network(cidr)
            if block.subnet_of(network):
                cidrs.add(block)
        return cidrs

    def block_cidrs(
        self, network: IPv4Network, vrf_table: int, vxlan_id: int
    ) -> set[IPv4Network]:
        return self._all_block_cidrs(network, vrf_table, vxlan_id)

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
        vxlan_id: int,
        live_pod_ips: dict[str, str],
        gateway_ip: str | None = None,
    ) -> int:
        removed = 0
        for item in self._block_items(network, vrf_table, vxlan_id):
            logging.info(f'Block item: {item}')
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

    def _delete_block(self, name: str) -> None:
        self.k8s_custom_api.delete_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, name
        )

    async def gc_empty_blocks(self, limit: int = 1, keep: int = 0) -> int:
        logging.info('Starting IPBlock GC')
        live_domains: set[tuple[int, int]] = set()
        default_vxlan = self._domain_defaults()[1]
        for ns in self.k8s_v1.list_namespace().items:
            metadata = ns.metadata
            if metadata is None:
                continue
            annotations = metadata.annotations or {}
            vrf_table = annotations.get('pyroute2.org/vrf')
            if vrf_table is None:
                continue
            vxlan_id = int(
                annotations.get('pyroute2.org/vxlan', default_vxlan)
            )
            live_domains.add((int(vrf_table), vxlan_id))

        orphaned_blocks: list[dict[str, Any]] = []
        empty_blocks_by_domain: dict[tuple[int, int], list[dict[str, Any]]] = (
            {}
        )
        for item in self._node_block_items():
            domain = (item['vrf_table'], item['vxlan_id'])
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
        self, network: IPv4Network, vrf_table: int, vxlan_id: int
    ) -> IPv4Network:
        used = self._all_block_cidrs(network, vrf_table, vxlan_id)
        for block in network.subnets(new_prefix=self.block_prefixlen):
            if block not in used:
                return block
        raise RuntimeError(f'no available IPBlocks in {network}')

    def _create_block(
        self,
        network: IPv4Network,
        cidr: IPv4Network,
        vrf_table: int,
        vxlan_id: int,
    ) -> dict[str, Any]:
        body = {
            'apiVersion': f'{IPBLOCK_GROUP}/{IPBLOCK_VERSION}',
            'kind': 'IPBlock',
            'metadata': {
                'name': self._block_name(cidr, vrf_table, vxlan_id),
                'labels': {
                    'pyroute2.org/node': self.node_name,
                    'pyroute2.org/vrf': str(vrf_table),
                    'pyroute2.org/vxlan': str(vxlan_id),
                },
            },
            'spec': {
                'cidr': cidr.compressed,
                'nodeName': self.node_name,
                'vrfTable': vrf_table,
                'vxlanId': vxlan_id,
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
                return self._get_block_by_cidr(
                    network, cidr, vrf_table, vxlan_id
                )
            raise

    def _get_block_by_cidr(
        self,
        network: IPv4Network,
        cidr: IPv4Network,
        vrf_table: int,
        vxlan_id: int,
    ) -> dict[str, Any]:
        for item in self._block_items(network, vrf_table, vxlan_id):
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
                'vxlanId': item['vxlan_id'],
            },
            'status': {
                'allocated': len(allocations),
                'capacity': self._block_capacity(cidr),
                'allocations': allocations,
            },
        }
        logging.info(f'Patching: {allocations}')
        self.k8s_custom_api.replace_cluster_custom_object_status(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, name, body
        )

    def _find_free_ip(
        self, cidr: IPv4Network, allocations: dict[str, str]
    ) -> IPv4Address | None:
        for ip in cidr.hosts():
            if ip.compressed not in allocations:
                return ip
        return None

    def _ip_for_address(
        self, network: IPv4Network, address: int
    ) -> IPv4Address:
        return IPv4Address(network[address])

    def _block_for_ip(
        self, network: IPv4Network, ip: IPv4Address
    ) -> IPv4Network:
        block = IPv4Network(f'{ip}/{self.block_prefixlen}', strict=False)
        if not block.subnet_of(network):
            raise ValueError(f'{ip} is outside of {network}')
        return block

    def _ensure_block_for_ip(
        self,
        network: IPv4Network,
        ip: IPv4Address,
        vrf_table: int,
        vxlan_id: int,
    ) -> dict[str, Any]:
        block_cidr = self._block_for_ip(network, ip)
        for item in self._block_items(network, vrf_table, vxlan_id):
            if item['cidr'] == block_cidr:
                return item
        return self._create_block(network, block_cidr, vrf_table, vxlan_id)

    def _select_block(
        self,
        network: IPv4Network,
        vrf_table: int,
        vxlan_id: int,
        ip: IPv4Address | None = None,
    ) -> dict[str, Any]:
        blocks = self._block_items(network, vrf_table, vxlan_id)
        if ip is not None:
            block_cidr = self._block_for_ip(network, ip)
            for item in blocks:
                if item['cidr'] == block_cidr:
                    return item
            return self._create_block(network, block_cidr, vrf_table, vxlan_id)

        for item in blocks:
            if item['allocated'] < item['capacity']:
                return item

        return self._create_block(
            network,
            self._next_free_block(network, vrf_table, vxlan_id),
            vrf_table,
            vxlan_id,
        )

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
                    item['vxlan_id'],
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

    def register_address(
        self,
        network: str,
        address: int,
        vrf_table: int,
        vxlan_id: int,
        node: str = '',
        is_gateway: bool = False,
        pod_uid: str = '',
    ) -> str:
        return self.inet_ntoa(network, address)

    async def allocate(
        self,
        network: IPv4Network,
        vrf_table: int | None = None,
        vxlan_id: int | None = None,
        is_gateway: bool = False,
        pod_uid: str = '',
        address: int = -1,
    ) -> str:
        vrf_table, vxlan_id = self._resolve_domain(vrf_table, vxlan_id)
        ref = pod_uid or ('gateway' if is_gateway else '')
        ip = self._ip_for_address(network, address) if address >= 0 else None
        block = self._select_block(network, vrf_table, vxlan_id, ip)
        allocations = dict(block['allocations'])

        if ip is None:
            ip = self._find_free_ip(block['cidr'], allocations)
            if ip is None:
                block = self._create_block(
                    network,
                    self._next_free_block(network, vrf_table, vxlan_id),
                    vrf_table,
                    vxlan_id,
                )
                allocations = dict(block['allocations'])
                ip = self._find_free_ip(block['cidr'], allocations)
                if ip is None:
                    raise RuntimeError(f'no free IPs in {block["cidr"]}')

        if ip.compressed in allocations:
            existing = allocations[ip.compressed]
            if existing and existing != ref:
                raise RuntimeError(f'IP {ip} already allocated to {existing}')
            return self.register_address(
                network.compressed,
                self.inet_aton(network, ip.compressed),
                vrf_table,
                vxlan_id,
                self.node_name,
                is_gateway,
                ref,
            )

        allocations[ip.compressed] = ref
        self._patch_block_status(block, allocations)
        return self.register_address(
            network.compressed,
            self.inet_aton(network, ip.compressed),
            vrf_table,
            vxlan_id,
            self.node_name,
            is_gateway,
            ref,
        )
