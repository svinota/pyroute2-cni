import logging
import struct

from pyroute2 import AsyncIPRoute
from pyroute2.netlink.nfnetlink.nftsocket import Cmp, Meta, Regs
from pyroute2.nftables.expressions import genex, ipv4addr, masq, verdict
from pyroute2.nftables.main import AsyncNFTables

from .crds.vrf_domain import VRFDomain


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


def ct_mark_match(mark):
    ret = []
    ret.append(
        genex('meta', {'key': Meta.NFT_META_MARK, 'dreg': Regs.NFT_REG_1})
    )
    ret.append(
        genex(
            'bitwise',
            {
                'sreg': Regs.NFT_REG_1,
                'dreg': Regs.NFT_REG_1,
                'len': 0x4,
                'op': 0x0,
                'mask': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', mark)]]
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
                'op': Cmp.NFT_CMP_EQ,
                'data': {
                    'attrs': [['NFTA_DATA_VALUE', struct.pack('I', mark)]]
                },
            },
        )
    )
    return ret


def nft_counter():
    ret = []
    ret.append(genex('counter', {'bytes': 0, 'packets': 0}))
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
        self.version = 'v2'

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
            magic = f'{self.version}|a=setup'
            for rule in [x async for x in await nft_main.get_rules()]:
                if rule.get('userdata') == magic:
                    break
            else:
                logging.info(f'fw: install setup rules with magic {magic}')
                await nft_main.rule(
                    'add',
                    table=self.table_name,
                    chain='ct-restore',
                    expressions=(
                        ct_mark_match(0x4000),
                        nft_counter(),
                        verdict(-5),
                    ),
                    userdata=magic,
                )
                await nft_main.rule(
                    'add',
                    table=self.table_name,
                    chain='ct-restore',
                    expressions=(nft_counter(), meta_mark()),
                    userdata=magic,
                )
                await nft_main.rule(
                    'add',
                    table=self.table_name,
                    chain='ct-manager',
                    expressions=(nft_counter(), jump('ct-mark')),
                    userdata=magic,
                )
                await nft_main.rule(
                    'add',
                    table=self.table_name,
                    chain='ct-manager',
                    expressions=(nft_counter(), jump('ct-restore')),
                    userdata=magic,
                )

    def magic(self, tag: str, vrf_id: int) -> str:
        return f'{self.version}|t={tag}|v={vrf_id}'

    async def ensure_nat_rules(
        self,
        vrf_id: int,
        nft: AsyncNFTables,
        prefix: str,
        prefixlen: int,
        default_link: int,
        vrf_bridge_index: int,
    ):
        magic = self.magic('nat', vrf_id)
        for rule in [x async for x in await nft.get_rules()]:
            if rule.get('userdata') == magic:
                logging.debug(f'fw: hit {magic}')
                return

        logging.info(f'fw: install nat rule with magic {magic}')
        #
        # general masquerade out
        await nft.rule(
            'add',
            table=self.table_name,
            chain='nat',
            expressions=(
                ipv4addr(src=f'{prefix}/{prefixlen}'),
                ipv4addr(dst=f'{prefix}/{prefixlen}', op=Cmp.NFT_CMP_NEQ),
                oif(default_link),
                nft_counter(),
                masq(),
            ),
            userdata=magic,
        )

    async def ensure_vrf_firewall(self, domain: VRFDomain) -> None:
        prefixlen = domain.prefixlen
        prefix = domain.prefix
        vrf_id = domain.vrf
        vrf_table = domain.table if domain.table is not None else domain.vrf
        async with AsyncIPRoute() as ipr_main:
            default_route = await ipr_main.route('get', dst='1.1.1.1')
            default_link = default_route[0].get('oif')
            logging.debug(f'fw: external interface {default_link}')
            vrf_bridge_index = await ipr_main.link_lookup(
                ifname=domain.bridge_name()
            )
            if not vrf_bridge_index:
                logging.info('fw: attachment not found, return')
                return

            #
            # install RPDB rule -- complement to the CT mark
            await ipr_main.ensure(
                ipr_main.rule,
                present=True,
                fwmark=vrf_id,
                table=vrf_table,
                priority=32000,
            )
            #
            # service VRF should have their routes globally available
            if domain.table < int(self.config['default']['service_vrf_max']):
                await ipr_main.ensure(
                    ipr_main.rule,
                    present=True,
                    dst=domain.prefix,
                    dst_len=domain.prefixlen,
                    table=vrf_table,
                    priority=12000,
                )

        async with AsyncNFTables() as nft_main:
            #
            # reconcile rules
            await self.ensure_nat_rules(
                vrf_id,
                nft_main,
                prefix,
                prefixlen,
                default_link,
                vrf_bridge_index[0],
            )

            magic = self.magic('mark', vrf_id)
            for rule in [x async for x in await nft_main.get_rules()]:
                if rule.get('userdata') == magic:
                    logging.debug(f'fw: hit {magic}')
                    break
            else:
                logging.info(f'fw: install mark rule with magic {magic}')
                await nft_main.rule(
                    'add',
                    table=self.table_name,
                    chain='ct-mark',
                    expressions=(
                        iif(vrf_bridge_index[0]),
                        ct_state_match(0x8),
                        ct_mark_set(vrf_id),
                    ),
                    userdata=magic,
                )
            logging.debug('fw: done')

    async def remove_vrf_firewall(self, domain: VRFDomain) -> None:
        vrf_id = domain.vrf

        async with AsyncNFTables() as nft_main:

            magic = self.magic('nat', vrf_id)
            for rule in [x async for x in await nft_main.get_rules()]:
                if rule.get('userdata') == magic:
                    await nft_main.rule(
                        'del',
                        table=self.table_name,
                        chain='nat',
                        handle=rule.get('handle'),
                    )

            magic = self.magic('mark', vrf_id)
            for rule in [x async for x in await nft_main.get_rules()]:
                if rule.get('userdata') == magic:
                    await nft_main.rule(
                        'del',
                        table=self.table_name,
                        chain='ct-mark',
                        handle=rule.get('handle'),
                    )

        async with AsyncIPRoute() as ipr_main:
            for rule in [x async for x in await ipr_main.get_rules()]:
                if rule.get('fwmark') == vrf_id:
                    await ipr_main.rule(
                        'del', fwmark=vrf_id, priority=rule.get('priority')
                    )
