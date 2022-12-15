import argparse
import os
import yaml
from asyncsnmplib.mib.mib_index import MIB_INDEX
from libprobe.probe import Probe
from lib.snmpquery import snmpquery
from lib.version import __version__ as version


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-c', '--config',
        required=True,
        help='specify a config file',
        type=str)
    args = parser.parse_args()

    assert os.path.exists(args.config), 'Cannot find config'

    with open(args.config, 'r') as file:
        probe = yaml.safe_load(file)

    probe_name = probe.get('name')
    assert isinstance(probe_name, str), 'Missing probe name'
    assert probe_name.startswith('snmp-'), 'Invalid probe name'

    checks = {
        check['name']: lambda *args: snmpquery(*args, tuple(
            MIB_INDEX[check['mib']][tp]
            for tp in check['types']
        ))
        for check in probe['checks']
    }

    probe = Probe(probe_name, version, checks)

    probe.start()
