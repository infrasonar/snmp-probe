import logging
from asyncsnmplib.mib.mib_index import MIB_INDEX
from collections import Counter
from libprobe.asset import Asset
from libprobe.exceptions import IncompleteResultException
from libprobe.severity import Severity
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    (MIB_INDEX['HOST-RESOURCES-MIB']['hrSWRunEntry'], True),
)


async def check_process(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state = await snmpquery(snmp, QUERIES, True)

    counts = Counter()
    itms = state.pop('hrSWRun', [])
    items = []
    for item in itms:
        name = item.get('Name')
        if None in (name,
                    item.get('Index'),
                    item.get('ID'),
                    item.get('Path'),
                    item.get('Parameters'),
                    item.get('Type'),
                    item.get('Status')):
            logging.warning(
                f'Process is missing a required metric: {item}; {asset}')
            continue
        item['name'] = f'{name}#{counts[name]}' if counts[name] > 0 else name
        counts[name] += 1
        items.append(item)

    result = {'process': items}

    if len(items) != len(itms):
        raise IncompleteResultException(
            msg=(
                'At least one process is missing a required property; '
                'View the SNMP probe log for more info'),
            result=result,
            severity=Severity.LOW)

    return result
