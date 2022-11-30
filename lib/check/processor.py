from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrProcessorEntry'],
)


async def check_processor(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    if 'hrProcessor' in state_data:
        cpus = [item.get('Load', 0) for item in state_data['hrProcessor']]
        aggr = sum(cpus) / len(cpus) if cpus else 0
        state_data['hrProcessorTotal'] = [{
            'name': 'processor',
            'LoadAverage': aggr
        }]

    return state_data
