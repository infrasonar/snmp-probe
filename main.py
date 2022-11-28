from libprobe.probe import Probe
from lib.check.snmp import check_snmp
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = {
        'snmp': check_snmp
    }

    probe = Probe("snmp", version, checks)

    probe.start()
