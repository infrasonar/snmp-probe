from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.exceptions import IgnoreCheckException
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrProcessorEntry'],
)


async def check_processor(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    hrProcessor = state_data.get('hrProcessor')
    if not hrProcessor:
        raise IgnoreCheckException

    cpus = [item.get('Load', 0) for item in hrProcessor]
    aggr = sum(cpus) / len(cpus) if cpus else 0.0
    state_data['hrProcessorTotal'] = [{
        'name': 'processor',
        'LoadAverage': aggr
    }]

    return state_data
