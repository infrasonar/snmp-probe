from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['RFC1213-MIB']['system'],
)


async def check_base(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)

    return {
        'base': [{
            (name[3:] if name.startswith('sys') else name): value
            for item in state.get('system', [])
            for name, value in item.items()
        }]
    }
