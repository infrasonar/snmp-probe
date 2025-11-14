from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.check import Check
from libprobe.exceptions import IncompleteResultException
from ..exceptions import ParseKeyException
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery
from ..utils import ip_mib_address

QUERIES = (
    (MIB_INDEX['IP-MIB']['ipAddressEntry'], True),
)


class CheckIpAddress(Check):
    key = 'ipAddress'
    unchanged_eol = 14400

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:

        snmp = get_snmp_client(asset, local_config, config)
        state = await snmpquery(snmp, QUERIES, True)

        rows = state['ipAddress']
        result = []
        missing = []
        for item in rows:
            try:
                result.append(ip_mib_address(item['name'], item))
            except ParseKeyException as e:
                missing.append(str(e))

        state['ipAddress'] = result
        if missing:
            oids = ', '.join(missing)
            msg = f'Unable to derive address info from oid(s): {oids}'
            raise IncompleteResultException(msg, state)
        return state
