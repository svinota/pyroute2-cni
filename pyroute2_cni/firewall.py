import base64
import logging
import struct

from pyroute2 import AsyncIPRoute
from pyroute2.netlink.nfnetlink.nftsocket import Cmp, Meta, Regs
from pyroute2.nftables.expressions import genex, ipv4addr, masq
from pyroute2.nftables.main import AsyncNFTables

from .kubernetes import get_namespace_labels


def ct_state_match(state):
    ret = []
    ret.append(genex('ct', {'key': 0x0, 'dreg': Regs.NFT_REG_1}))
    ret.append(
        genex(
            'bitwise',
            {
                'sreg': Regs.NFT_REG_1,
                'dreg': Regs.NFT_REG_1,
                'len': 0x4,
                'op': 0x0,
                'mask': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', state)]]
                },
                'xor': {'attrs': [['NFTA_DATA_VALUE', struct.pack('I', 0x0)]]},
            },
        )
    )
    ret.append(
        genex(
            'cmp',
            {
                'sreg': Regs.NFT_REG_1,
                'op': Cmp.NFT_CMP_NEQ,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', 0x0)]]
                },
            },
        )
    )
    return ret


def meta_mark():
    ret = []
    ret.append(genex('ct', {'dreg': Regs.NFT_REG_1, 'key': 0x3}))
    ret.append(
        genex('meta', {'sreg': Regs.NFT_REG_1, 'key': Meta.NFT_META_MARK})
    )
    return ret


def ct_mark_set(mark):
    ret = []
    ret.append(
        genex(
            'immediate',
            {
                'dreg': Regs.NFT_REG_1,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', mark)]]
                },
            },
        )
    )
    ret.append(genex('ct', {'sreg': Regs.NFT_REG_1, 'key': 0x3}))
    return ret


def iif(index):
    ret = []
    ret.append(
        genex('meta', {'key': Meta.NFT_META_IIF, 'dreg': Regs.NFT_REG_1})
    )
    ret.append(
        genex(
            'cmp',
            {
                'sreg': Regs.NFT_REG_1,
                'op': Cmp.NFT_CMP_EQ,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', index)]]
                },
            },
        )
    )
    return ret


def oif(index):
    ret = []
    ret.append(
        genex('meta', {'key': Meta.NFT_META_OIF, 'dreg': Regs.NFT_REG_1})
    )
    ret.append(
        genex(
            'cmp',
            {
                'sreg': Regs.NFT_REG_1,
                'op': Cmp.NFT_CMP_EQ,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', index)]]
                },
            },
        )
    )
    return ret


class FirewallManager:
    def __init__(self, config):
        self.config = config

    async def ensure_system_firewall(self, namespace: str) -> None:
        config = self.config
        table_name = 'pyroute2-cni'
        labels = get_namespace_labels(namespace)
        prefixlen = labels.get(
            'pyroute2.org/prefixlen', config['default']['prefixlen']
        )
        prefix = labels.get('pyroute2.org/prefix', config['default']['prefix'])
        vrf_table = int(
            labels.get('pyroute2.org/vrf', config['default']['vrf'])
        )
        vrf_bridge_name = f'br-{vrf_table}'
        async with AsyncIPRoute() as ipr_main:
            default_route = await ipr_main.route('get', dst='1.1.1.1')
            default_link = default_route[0].get('oif')
            logging.info(f'fw: external interface {default_link}')
            vrf_bridge_index = await ipr_main.link_lookup(
                ifname=vrf_bridge_name
            )
        async with AsyncNFTables() as nft_main:
            # reconcile table
            for table in [x async for x in await nft_main.get_tables()]:
                if table.get('name') == table_name:
                    break
            else:
                await nft_main.table('add', name=table_name)

            # reconcile chains

            # prerouting set mark
            for table, chain in [
                (x.get('table'), x.get('name'))
                async for x in await nft_main.get_chains()
            ]:
                if (table == table_name) and (chain == 'mark-pre'):
                    break
            else:
                await nft_main.chain(
                    'add',
                    table=table_name,
                    name='mark-pre',
                    hook='prerouting',
                    type='filter',
                    policy=1,
                )

            # prerouting set mark
            for table, chain in [
                (x.get('table'), x.get('name'))
                async for x in await nft_main.get_chains()
            ]:
                if (table == table_name) and (chain == 'masquerade'):
                    break
            else:
                await nft_main.chain(
                    'add',
                    table=table_name,
                    name='masquerade',
                    hook='postrouting',
                    type='nat',
                    policy=1,
                )

            # reconcile rule
            magic = '0x42 ' + base64.b64encode(
                f'{prefix}/{prefixlen}'.encode('ascii')
            ).decode('ascii')
            for rule in [x async for x in await nft_main.get_rules()]:
                if rule.get('userdata') == magic:
                    break
            else:
                logging.info(f'fw: install nat rule with magic {magic}')
                await nft_main.rule(
                    'add',
                    table=table_name,
                    chain='masquerade',
                    expressions=(
                        ipv4addr(src=f'{prefix}/{prefixlen}'),
                        ipv4addr(
                            dst=f'{prefix}/{prefixlen}', op=Cmp.NFT_CMP_NEQ
                        ),
                        oif(default_link),
                        masq(),
                    ),
                    userdata=magic,
                )
                await nft_main.rule(
                    'add',
                    table=table_name,
                    chain='mark-pre',
                    expressions=(
                        iif(vrf_bridge_index[0]),
                        ct_state_match(0x8),
                        ct_mark_set(vrf_table),
                    ),
                )
                await nft_main.rule(
                    'add',
                    table=table_name,
                    chain='mark-pre',
                    expressions=(meta_mark(),),
                )
                logging.info('fw: done')
