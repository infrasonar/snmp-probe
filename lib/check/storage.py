from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrFSEntry'],
    MIB_INDEX['HOST-RESOURCES-MIB']['hrStorageEntry'],
)


async def check_storage(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    snmp = get_snmp_client(asset, asset_config, check_config)
    state_data = await snmpquery(snmp, QUERIES)

    fs_types = {item.get('StorageIndex'): item.get('hrFSType')
                for item in state_data.pop('hrFS', [])}
    for item in state_data['hrStorage']:
        if 'Index' in item:
            item['FsType'] = fs_types.get(item['Index'])

        if 'AllocationUnits' in item:
            total = item.get('Size', 0) * \
                item['AllocationUnits']
            used = item.get('Used', 0) * \
                item['AllocationUnits']
            free = total - used
            item['SizeInBytes'] = total
            item['FreeInBytes'] = free
            item['UsedInBytes'] = used
            if total:
                free_percentage = 100 * free / total if total else None
                used_percentage = 100 * used / total if total else None
                item['FreePercentage'] = free_percentage
                item['UsedPercentage'] = used_percentage

    return state_data
