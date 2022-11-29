from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrDeviceEntry'],
)


async def check_device(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    return state_data
