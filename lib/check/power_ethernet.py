from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['POWER-ETHERNET-MIB']['pethMainPseEntry'],
    MIB_INDEX['POWER-ETHERNET-MIB']['pethPsePortEntry'],
)


async def check_power_ethernet(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)
    return state
