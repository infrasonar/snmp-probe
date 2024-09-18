from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['UDP-MIB']['udp'],
)

_64_BIT_COUNTERS = (
    'HCInDatagrams',
    'HCOutDatagrams',
)


async def check_udp(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state = await snmpquery(snmp, QUERIES)
    for item in state.get('udp', []):
        for _64_bit_name in _64_BIT_COUNTERS:
            if _64_bit_name in item:
                _32_bit_name = _64_bit_name[2:]
                item[_32_bit_name] = item.pop(_64_bit_name)

    return state
