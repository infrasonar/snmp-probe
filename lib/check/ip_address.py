from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery
from ..utils import ip_mib_address

QUERIES = (
    MIB_INDEX['IP-MIB']['ipAddressEntry'],
)


async def check_ip_address(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)

    for item in state['ipAddressEntry']:
        ip_mib_address(item['name'], item)

    return state
