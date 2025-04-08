from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery
from ..utils import tcp_mib_connection

QUERIES = (
    (MIB_INDEX['TCP-MIB']['tcpConnectionEntry'], True),
)


async def check_tcp_connection(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state = await snmpquery(snmp, QUERIES, True)

    for item in state['tcpConnection']:
        tcp_mib_connection(item['name'], item)

    return state
