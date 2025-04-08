from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    (MIB_INDEX['RFC1213-MIB']['system'], False),
)


async def check_base(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state = await snmpquery(snmp, QUERIES, True)

    return {
        'base': [{
            (name[3:] if name.startswith('sys') else name): value
            for item in state.get('system', [])
            for name, value in item.items()
        }]
    }
