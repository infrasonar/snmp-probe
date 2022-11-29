from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['HOST-RESOURCES-MIB']['hrFSEntry'],
    MIB_INDEX['HOST-RESOURCES-MIB']['hrStorageEntry'],
)


async def check_storage(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    if 'hrStorageEntry' in state_data:
        fs_types = {item.get('hrFSStorageIndex'): item.get('hrFSType')
                    for item in state_data.pop('hrFSEntry', [])}
        for item in state_data['hrStorageEntry']:
            if 'hrStorageIndex' in item:
                item['hrFSType'] = fs_types.get(item['hrStorageIndex'])

            if 'hrStorageAllocationUnits' in item:
                total = item.get('hrStorageSize', 0) * \
                    item['hrStorageAllocationUnits']
                used = item.get('hrStorageUsed', 0) * \
                    item['hrStorageAllocationUnits']
                free = total - used
                free_percentage = 100 * free / total if total else None
                used_percentage = 100 * used / total if total else None
                item['hrStorageSizeInBytes'] = total
                item['hrStorageFreeInBytes'] = free
                item['hrStorageUsedInBytes'] = used
                item['hrStorageFreePercentage'] = free_percentage
                item['hrStorageUsedPercentage'] = used_percentage

    return state_data
