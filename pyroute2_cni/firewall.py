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


def jump(chain):
    ret = []
    ret.append(
        genex(
            'immediate',
            {
                'dreg': Regs.NFT_REG_VERDICT,
                'data': {
                    'attrs': [
                        [
                            'NFTA_DATA_VERDICT',
                            {
                                'attrs': [
                                    ('NFTA_VERDICT_CODE', -3),
                                    ('NFTA_VERDICT_CHAIN', chain),
                                ]
                            },
                        ]
                    ]
                },
            },
        )
    )
    return ret


class FirewallManager:
    def __init__(self, config):
        self.config = config
        self.has_setup = False
        self.table_name = 'pyroute2-cni'

    async def setup(self) -> None:
        if self.has_setup:
            return
        self.has_setup = True

        async with AsyncNFTables() as nft_main:
            # reconcile table
            for table in [x async for x in await nft_main.get_tables()]:
                if table.get('name') == self.table_name:
                    break
            else:
                await nft_main.table('add', name=self.table_name)

            # reconcile chains

            # 8<-------------------------------------------------------
            # chain: NAT
            #
            # here all the NAT rules will be installed
            for table, chain in [
                (x.get('table'), x.get('name'))
                async for x in await nft_main.get_chains()
            ]:
                if (table == self.table_name) and (chain == 'nat'):
                    break
            else:
                await nft_main.chain(
                    'add',
                    table=self.table_name,
                    name='nat',
                    hook='postrouting',
                    type='nat',
                    policy=1,
                )

            # 8<-------------------------------------------------------
            # chain: ct-manager
            #
            # root chain for CT rules
            for table, chain in [
                (x.get('table'), x.get('name'))
                async for x in await nft_main.get_chains()
            ]:
                if (table == self.table_name) and (chain == 'ct-manager'):
                    break
            else:
                await nft_main.chain(
                    'add',
                    table=self.table_name,
                    name='ct-manager',
                    hook='prerouting',
                    type='filter',
                    policy=1,
                )

            # 8<-------------------------------------------------------
            # chain: ct-mark
            #
            # here are all the rules to mark new flows
            for table, chain in [
                (x.get('table'), x.get('name'))
                async for x in await nft_main.get_chains()
            ]:
                if (table == self.table_name) and (chain == 'ct-mark'):
                    break
            else:
                await nft_main.chain(
                    'add', table=self.table_name, name='ct-mark'
                )

            # 8<-------------------------------------------------------
            # chain: ct-restore
            for table, chain in [
                (x.get('table'), x.get('name'))
                async for x in await nft_main.get_chains()
            ]:
                if (table == self.table_name) and (chain == 'ct-restore'):
                    break
            else:
                await nft_main.chain(
                    'add', table=self.table_name, name='ct-restore'
                )

            # 8<=======================================================
            # default unconditional rules
            await nft_main.rule(
                'add',
                table=self.table_name,
                chain='ct-restore',
                expressions=(meta_mark(),),
            )
            await nft_main.rule(
                'add',
                table=self.table_name,
                chain='ct-manager',
                expressions=(jump('ct-mark'),),
            )
            await nft_main.rule(
                'add',
                table=self.table_name,
                chain='ct-manager',
                expressions=(jump('ct-restore'),),
            )

    async def ensure_system_firewall(self, namespace: str) -> None:
        config = self.config
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
                    table=self.table_name,
                    chain='nat',
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
                if vrf_bridge_index:
                    await nft_main.rule(
                        'add',
                        table=self.table_name,
                        chain='ct-mark',
                        expressions=(
                            iif(vrf_bridge_index[0]),
                            ct_state_match(0x8),
                            ct_mark_set(vrf_table),
                        ),
                    )
                logging.info('fw: done')
