from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery
from ..utils import InterfaceLookup


QUERIES = (
    MIB_INDEX['IF-MIB']['ifEntry'],
    MIB_INDEX['BRIDGE-MIB']['dot1dStpPortEntry'],
    MIB_INDEX['BRIDGE-MIB']['dot1dBasePortEntry']
)


async def check_lldp(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)

    if_entry = InterfaceLookup.get(asset.id)
    if if_entry is None:
        state_data = await snmpquery(snmp, QUERIES, True)
        if_entry = InterfaceLookup.set(asset.id, state_data.get('if', []))
    else:
        state_data = await snmpquery(snmp, QUERIES[1:], True)

    itms = state_data.get('dot1dStpPort', [])
    base_port_entry = {
        i.pop('name'): i
        for i in state_data.get('dot1dBasePort', [])}
    for item in itms:
        key = item['name']

        try:
            base_port_item = base_port_entry[key]
            if_item = if_entry[base_port_item['IfIndex']]
            item['Interface'] = if_item['Descr']
        except Exception:
            continue

    return {
        'lldp': itms
    }
