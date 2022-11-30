from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery
from ..utils import tcp_mib_connection

QUERIES = (
    MIB_INDEX['TCP-MIB']['tcpConnectionEntry'],
)


async def check_tcp_connection(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)

    for item in state['tcpConnection']:
        tcp_mib_connection(item['name'], item)

    return state
