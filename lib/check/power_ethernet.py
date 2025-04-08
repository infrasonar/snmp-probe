from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    (MIB_INDEX['POWER-ETHERNET-MIB']['pethMainPseEntry'], True),
    (MIB_INDEX['POWER-ETHERNET-MIB']['pethPsePortEntry'], True),
)


async def check_power_ethernet(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state = await snmpquery(snmp, QUERIES, True)
    return state
