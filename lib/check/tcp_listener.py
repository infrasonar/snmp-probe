from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery
from ..utils import tcp_mib_listener

QUERIES = (
    MIB_INDEX['TCP-MIB']['tcpListenerEntry'],
)


async def check_tcp_listener(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)

    for item in state['tcpListenerEntry']:
        tcp_mib_listener(item['name'], item)

    return state
