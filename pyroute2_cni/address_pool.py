import asyncio
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
    node: str
    pod_uid: str
    is_gateway: bool
    network: str
    address: str


class AddressPool:
    def __init__(
        self, name: str, node_name: str, config: ConfigParser
    ) -> None:
        self.allocated: dict[tuple[str, int], AddressMetadata] = {}
        self.name = name
        self.node_name = node_name
        self.config = config
        self.block_prefixlen = int(
            self.config['default'].get(
                'ipblocklen', self.config['default']['prefixlen']
            )
        )
        self.k8s = self._load_k8s_client()
        self.lock = asyncio.Lock()

    def _load_k8s_client(self) -> k8s_client.CustomObjectsApi:
        try:
            k8s_config.load_incluster_config()
        except Exception:
            k8s_config.load_kube_config()
        return k8s_client.CustomObjectsApi()

    def _block_name(self, cidr: IPv4Network) -> str:
        safe_node = ''.join(
            x if x.isalnum() or x == '-' else '-'
            for x in self.node_name.lower()
        )
        safe_cidr = str(cidr.network_address).replace('.', '-')
        return f'{safe_node}-{safe_cidr}-{cidr.prefixlen}'

    def _block_capacity(self, cidr: IPv4Network) -> int:
        return max(cidr.num_addresses - 2, 0)

    def _raw_block_items(self) -> list[dict[str, Any]]:
        response = self.k8s.list_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL
        )
        return response.get('items', [])

    def _parse_block(self, item: dict[str, Any]) -> dict[str, Any]:
        metadata = item.get('metadata') or {}
        spec = item.get('spec') or {}
        status = item.get('status') or {}
        cidr = spec.get('cidr')
        if not cidr:
            raise KeyError('cidr')
        block = IPv4Network(cidr)
        allocations = status.get('allocations') or {}
        name = metadata.get('name') or item.get('name')
        if not name:
            raise KeyError('name')
        return {
            'name': name,
            'node_name': spec.get('nodeName') or '',
            'cidr': block,
            'allocations': allocations,
            'allocated': int(status.get('allocated') or len(allocations)),
            'capacity': int(
                status.get('capacity') or self._block_capacity(block)
            ),
        }

    def _block_items(self, network: IPv4Network) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block['node_name'] != self.node_name:
                continue
            if block['cidr'].subnet_of(network):
                result.append(block)
        result.sort(
            key=lambda x: (int(x['cidr'].network_address), x['cidr'].prefixlen)
        )
        return result

    def _all_block_cidrs(self, network: IPv4Network) -> set[IPv4Network]:
        response = self.k8s.list_cluster_custom_object(
            IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL
        )
        cidrs: set[IPv4Network] = set()
        for item in response.get('items', []):
            spec = item.get('spec') or {}
            cidr = spec.get('cidr')
            if not cidr:
                continue
            block = IPv4Network(cidr)
            if block.subnet_of(network):
                cidrs.add(block)
        return cidrs

    def _node_block_items(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for item in self._raw_block_items():
            block = self._parse_block(item)
            if block['node_name'] != self.node_name:
                continue
            result.append(
                {
                    'name': block['name'],
                    'cidr': block['cidr'],
                    'allocations': block['allocations'],
                }
            )
        return result

    def _next_free_block(self, network: IPv4Network) -> IPv4Network:
        used = self._all_block_cidrs(network)
        for block in network.subnets(new_prefix=self.block_prefixlen):
            if block not in used:
                return block
        raise RuntimeError(f'no available IPBlocks in {network}')

    def _create_block(
        self, network: IPv4Network, cidr: IPv4Network
    ) -> dict[str, Any]:
        body = {
            'apiVersion': f'{IPBLOCK_GROUP}/{IPBLOCK_VERSION}',
            'kind': 'IPBlock',
            'metadata': {
                'name': self._block_name(cidr),
                'labels': {'pyroute2.org/node': self.node_name},
            },
            'spec': {'cidr': cidr.compressed, 'nodeName': self.node_name},
        }
        try:
            created = cast(
                dict[str, Any],
                self.k8s.create_cluster_custom_object(
                    IPBLOCK_GROUP, IPBLOCK_VERSION, IPBLOCK_PLURAL, body
                ),
            )
            return self._parse_block(created)
        except ApiException as err:
            if err.status == 409:
                return self._get_block_by_cidr(network, cidr)
            raise

    def _get_block_by_cidr(
        self, network: IPv4Network, cidr: IPv4Network
    ) -> dict[str, Any]:
        for item in self._block_items(network):
            if item['cidr'] == cidr:
                return item
        raise KeyError(f'IPBlock {cidr} not found')

    def _patch_block_status(
        self, name: str, cidr: IPv4Network, allocations: dict[str, str]
    ) -> None:
        body = {
            'status': {
                'allocated': len(allocations),
                'capacity': self._block_capacity(cidr),
                'allocations': allocations,
            }
        }
        self.k8s.patch_cluster_custom_object_status(
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
        self, network: IPv4Network, ip: IPv4Address
    ) -> dict[str, Any]:
        block_cidr = self._block_for_ip(network, ip)
        for item in self._block_items(network):
            if item['cidr'] == block_cidr:
                return item
        return self._create_block(network, block_cidr)

    def _select_block(
        self, network: IPv4Network, ip: IPv4Address | None = None
    ) -> dict[str, Any]:
        blocks = self._block_items(network)
        if ip is not None:
            block_cidr = self._block_for_ip(network, ip)
            for item in blocks:
                if item['cidr'] == block_cidr:
                    return item
            return self._create_block(network, block_cidr)

        for item in blocks:
            if item['allocated'] < item['capacity']:
                return item

        return self._create_block(network, self._next_free_block(network))

    def inet_aton(self, network: IPv4Network, address: str) -> int:
        return (
            struct.unpack('>I', IPv4Address(address).packed)[0]
            & struct.unpack('>I', network.hostmask.packed)[0]
        )

    def inet_ntoa(self, network: str, address: int) -> str:
        return IPv4Network(network)[address].compressed

    def unregister_address(self, pod_uid: str) -> AddressMetadata:
        logging.info(f'pod_uid: {pod_uid}')
        address = None
        for address, metadata in tuple(self.allocated.items()):
            logging.info(f'L address {address}, pod_uid: {metadata.pod_uid}')
            logging.info(f'L {metadata.pod_uid == pod_uid}')
            logging.info(f'L {type(metadata.pod_uid)} -- {type(pod_uid)}')
            if metadata.pod_uid == pod_uid:
                break
        else:
            raise KeyError('address not allocated')
        return self.allocated.pop(address)

    async def release(self, pod_uid: str) -> AddressMetadata:
        async with self.lock:
            for item in self._node_block_items():
                allocations = dict(item['allocations'])
                for ip, ref in tuple(allocations.items()):
                    if ref != pod_uid:
                        continue
                    try:
                        metadata = self.unregister_address(pod_uid)
                    except KeyError:
                        metadata = AddressMetadata(
                            self.node_name,
                            pod_uid,
                            False,
                            item['cidr'].compressed,
                            ip,
                        )
                    allocations.pop(ip, None)
                    self._patch_block_status(
                        item['name'], item['cidr'], allocations
                    )
                    return metadata
        raise KeyError('address not allocated')

    def register_address(
        self,
        network: str,
        address: int,
        node: str = '',
        is_gateway: bool = False,
        pod_uid: str = '',
    ) -> str:
        ret = self.inet_ntoa(network, address)
        self.allocated[(network, address)] = AddressMetadata(
            node, pod_uid, is_gateway, network, ret
        )
        return ret

    async def allocate(
        self,
        network: IPv4Network,
        is_gateway: bool = False,
        pod_uid: str = '',
        address: int = -1,
    ) -> str:
        async with self.lock:
            ref = pod_uid or ('gateway' if is_gateway else '')
            ip = (
                self._ip_for_address(network, address)
                if address >= 0
                else None
            )
            block = self._select_block(network, ip)
            allocations = dict(block['allocations'])

            if ip is None:
                ip = self._find_free_ip(block['cidr'], allocations)
                if ip is None:
                    block = self._create_block(
                        network, self._next_free_block(network)
                    )
                    allocations = dict(block['allocations'])
                    ip = self._find_free_ip(block['cidr'], allocations)
                    if ip is None:
                        raise RuntimeError(f'no free IPs in {block["cidr"]}')

            if ip.compressed in allocations:
                existing = allocations[ip.compressed]
                if existing and existing != ref:
                    raise RuntimeError(
                        f'IP {ip} already allocated to {existing}'
                    )
                return self.register_address(
                    network.compressed,
                    self.inet_aton(network, ip.compressed),
                    self.node_name,
                    is_gateway,
                    ref,
                )

            allocations[ip.compressed] = ref
            self._patch_block_status(block['name'], block['cidr'], allocations)
            return self.register_address(
                network.compressed,
                self.inet_aton(network, ip.compressed),
                self.node_name,
                is_gateway,
                ref,
            )
