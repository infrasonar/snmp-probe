from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.exceptions import CheckException
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    (MIB_INDEX['UDP-MIB']['udp'], True),
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
    state = await snmpquery(snmp, QUERIES, True)
    for item in state.get('udp', []):
        for _64_bit_name in _64_BIT_COUNTERS:
            if _64_bit_name in item:
                _32_bit_name = _64_bit_name[2:]
                item[_32_bit_name] = item.pop(_64_bit_name)

    try:
        items = state['udp']
        assert len(items)
        # There is an item with a 'name' metric in case the root oid can be
        # found, and only nested oids are present.
        # We filter out (is_table=False) these.
        item = items[0]
        assert len(item) > 1
    except Exception:
        raise CheckException(
            'SNMP is connected, but this device does not provide UDP '
            'information. You may want to disable this check.')

    return state
