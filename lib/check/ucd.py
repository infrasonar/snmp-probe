from asyncsnmplib.mib.mib_index import MIB_INDEX
from collections import Counter
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['UCD-SNMP-MIB']['memory'],
    MIB_INDEX['UCD-SNMP-MIB']['dskEntry'],
    MIB_INDEX['UCD-DISKIO-MIB']['diskIOEntry'],
)

_TO_BYTES = (
    'memAvailReal',
    'memAvailSwap',
    'memBuffer',
    'memCached',
    'memMinimumSwap',
    'memShared',
    'memTotalFree',
    'memTotalReal',
    'memTotalSwap',
)


async def check_ucd(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    for item in state_data.get('memory', []):
        for metric in _TO_BYTES:
            if metric in item:
                item[metric] *= 1024

        if 'memTotalReal' in item and 'memAvailReal' in item:
            item['memUsedReal'] = item['memTotalReal'] - item['memAvailReal']
            item['memUsedRealPercentage'] = \
                100 * item['memUsedReal'] / item['memTotalReal'] \
                if item['memTotalReal'] else None
            item['memAvailRealPercentage'] = \
                100 * item['memAvailReal'] / item['memTotalReal'] \
                if item['memTotalReal'] else None

        if 'memTotalSwap' in item and 'memAvailSwap' in item:
            item['memUsedSwap'] = item['memTotalSwap'] - item['memAvailSwap']
            item['memUsedSwapPercentage'] = \
                100 * item['memUsedSwap'] / item['memTotalSwap'] \
                if item['memTotalSwap'] else None
            item['memFreeSwapPercentage'] = \
                100 * item['memAvailSwap'] / item['memTotalSwap'] \
                if item['memTotalSwap'] else None

        # UCD-SNMP-MIB says:
        # This object will not be implemented on hosts where the
        # underlying operating system does not distinguish text
        # pages from other uses of physical memory."
        # this rule also applies to memBuffer and memCached
        if 'memUsedReal' in item and 'memBuffer' in item and \
                'memCached' in item:
            item['memUsedHuman'] = item['memUsedReal'] - item['memBuffer'] \
                - item['memCached']
            item['memUsedHumanPercentage'] = \
                100 * item['memUsedHuman'] / item['memTotalReal'] \
                if item['memTotalReal'] else None

    counts = Counter()
    for item in state_data.get('diskIO', []):
        name = item['Device']
        idx = counts[name]
        counts[name] += 1
        item['name'] = f'{name}_{idx}' if idx else name

    counts = Counter()
    for item in state_data.get('dsk', []):
        name = item['Device']
        idx = counts[name]
        counts[name] += 1
        item['name'] = f'{name}_{idx}' if idx else name

    return state_data
