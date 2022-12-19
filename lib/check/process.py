import logging
from asyncsnmplib.mib.mib_index import MIB_INDEX
from collections import Counter
from libprobe.asset import Asset
from libprobe.exceptions import IncompleteResultException
from libprobe.severity import Severity
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
    items = []
    for item in itms:
        name = item.get('Name')
        if None in (name, item.get('Path')):
            logging.warning(
                f'Process is missing a required metric: {item}; {asset}')
            continue
        item['name'] = f'{name}#{counts[name]}' if counts[name] > 0 else name
        counts[name] += 1
        items.append(item)

    result = {'process': items}

    if len(items) != len(itms):
        raise IncompleteResultException(
            msg='At least one process',
            result=result,
            severity=Severity.LOW)

    return result
