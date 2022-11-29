from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['RFC1213-MIB']['tcpConnEntry'],
)


async def check_tcp_conn(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)
    return state
