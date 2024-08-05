from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.exceptions import IgnoreCheckException
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['IP-MIB']['ip'],
)


async def check_ip(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)
    try:
        assert len(state['ip'])
    except Exception:
        raise IgnoreCheckException
    return state
