from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.exceptions import IncompleteResultException
from ..exceptions import ParseKeyException
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery
from ..utils import ip_mib_address

QUERIES = (
    (MIB_INDEX['IP-MIB']['ipAddressEntry'], True),
)


async def check_ip_address(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
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
