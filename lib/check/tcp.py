from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['TCP-MIB']['tcp'],
)

_64_BIT_COUNTERS = (
    'HCInSegs',
    'HCOutSegs',
)


async def check_tcp(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)
    for item in state.get('tcp', []):
        for _64_bit_name in _64_BIT_COUNTERS:
            if _64_bit_name in item:
                _32_bit_name = _64_bit_name[2:]
                item[_32_bit_name] = item.pop(_64_bit_name)

    return state
