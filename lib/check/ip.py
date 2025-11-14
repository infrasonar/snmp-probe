from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.check import Check
from libprobe.exceptions import CheckException
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    (MIB_INDEX['IP-MIB']['ip'], False),
)


class CheckIp(Check):
    key = 'ip'
    # unchanged_eol = 14400

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:

        snmp = get_snmp_client(asset, local_config, config)
        state = await snmpquery(snmp, QUERIES, True)

        try:
            items = state['ip']
            assert len(items)
            # There is an item with a 'name' metric in case the root oid can be
            # found, and only nested oids are present.
            # We filter out (is_table=False) these.
            item = items[0]
            assert len(item) > 1
        except Exception:
            raise CheckException(
                'SNMP is connected, but this device does not provide general '
                'IP information. You may want to disable this check.')

        return state
