from libprobe.probe import Probe
from lib.check.base import check_base
from lib.check.device import check_device
from lib.check.entity import check_entity
from lib.check.interface import check_interface
from lib.check.ip import check_ip
from lib.check.ip_address import check_ip_address
from lib.check.ip_forward import check_ip_forward
from lib.check.lldp import check_lldp
from lib.check.power_ethernet import check_power_ethernet
from lib.check.process import check_process
from lib.check.processor import check_processor
from lib.check.sensor import check_sensor
from lib.check.storage import check_storage
from lib.check.system import check_system
from lib.check.tcp import check_tcp
from lib.check.tcp_connection import check_tcp_connection
from lib.check.tcp_listener import check_tcp_listener
from lib.check.ucd import check_ucd
from lib.check.udp import check_udp
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = {
        'base': check_base,
        'device': check_device,
        'entity': check_entity,
        'interface': check_interface,
        'ip': check_ip,
        'ipAddress': check_ip_address,
        'ipForward': check_ip_forward,
        'lldp': check_lldp,
        'powerEthernet': check_power_ethernet,
        'process': check_process,
        'processor': check_processor,
        'sensor': check_sensor,
        'storage': check_storage,
        'system': check_system,
        'tcp': check_tcp,
        'tcpConnection': check_tcp_connection,
        'tcpListener': check_tcp_listener,
        'ucd': check_ucd,
        'udp': check_udp,
    }

    probe = Probe("snmp", version, checks)

    probe.start()
