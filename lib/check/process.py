from asyncsnmplib.mib.mib_index import MIB_INDEX
from collections import Counter
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrSWRunEntry'],
)


async def check_process(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state = await snmpquery(asset, asset_config, check_config, QUERIES)

    counts = Counter()
    itms = state['hrSWRunEntry']
    for item in itms:
        runName = item.get('hrSWRunName')
        if runName is not None:
            item['name'] = \
                '{}#{}'.format(runName, counts[runName]) \
                if counts[runName] > 0 else runName
            counts[runName] += 1

    return {
        'process': itms,
        'processCount': [{'name': 'processCount', 'count': len(itms)}],
    }
