from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.asset import Asset
from libprobe.check import Check
from libprobe.exceptions import IgnoreCheckException
from ..snmpclient import get_snmp_client
from ..snmpquery import snmpquery

QUERIES = (
    (MIB_INDEX['HOST-RESOURCES-MIB']['hrProcessorEntry'], True),
)


class CheckProcessor(Check):
    key = 'processor'

    @staticmethod
    async def run(asset: Asset, local_config: dict, config: dict) -> dict:

        snmp = get_snmp_client(asset, local_config, config)
        state_data = await snmpquery(snmp, QUERIES, True)

        hrProcessor = state_data.get('hrProcessor')
        if not hrProcessor:
            raise IgnoreCheckException

        cpus = [
            item
            for item in hrProcessor
            if item.get('Load') is not None
        ]
        cpu_load_total = sum(item['Load'] for item in cpus)
        aggr = cpu_load_total / len(cpus) if cpus else 0.0

        return {
            'hrProcessor': cpus,
            'hrProcessorTotal': [{
                'name': 'processor',
                'LoadAverage': aggr
            }]
        }
