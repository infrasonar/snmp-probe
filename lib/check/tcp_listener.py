from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.check import Check
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery
from ..utils import tcp_mib_listener

QUERIES = (
    (MIB_INDEX['TCP-MIB']['tcpListenerEntry'], True),
)


class CheckTcpListener(Check):
    key = 'tcpListener'
    unchanged_eol = 14400

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:

        snmp = get_snmp_client(asset, local_config, config)
        state = await snmpquery(snmp, QUERIES, True)

        for item in state['tcpListener']:
            tcp_mib_listener(item['name'], item)

        return state
