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
    itms = state.pop('hrSWRun', [])
    for item in itms:
        run_name = item.get('Name')
        if run_name is not None:
            item['name'] = \
                f'{run_name}#{counts[run_name]}' \
                if counts[run_name] > 0 else run_name
            counts[run_name] += 1

    return {
        'process': itms,
        'processCount': [{'name': 'processCount', 'Count': len(itms)}],
    }
