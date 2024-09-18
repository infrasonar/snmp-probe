from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.exceptions import IgnoreCheckException
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrSystem'],
)


async def check_system(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state = await snmpquery(snmp, QUERIES)
    try:
        assert len(state['hrSystem'])
    except Exception:
        raise IgnoreCheckException

    return state
