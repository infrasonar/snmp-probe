from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.check import Check
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery
from ..utils import InterfaceLookup


QUERIES = (
    (MIB_INDEX['IF-MIB']['ifEntry'], True),
    (MIB_INDEX['BRIDGE-MIB']['dot1dStpPortEntry'], True),
    (MIB_INDEX['BRIDGE-MIB']['dot1dBasePortEntry'], True),
)


class CheckLldp(Check):
    key = 'lldp'
    unchanged_eol = 14400

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:

        snmp = get_snmp_client(asset, local_config, config)

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
