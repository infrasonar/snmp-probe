from libprobe.probe import Probe
from lib.check.processor import check_processor
from lib.check.device import check_device
from lib.check.interface import check_interface
from lib.check.ip_address import check_ip_address
from lib.check.ip_forward import check_ip_forward
from lib.check.process import check_process
from lib.check.storage import check_storage
from lib.check.system import check_system
from lib.check.tcp_connection import check_tcp_connection
from lib.check.tcp_listener import check_tcp_listener
from lib.check.entity import check_entity
from lib.check.entity_sensor import check_entity_sensor
from lib.check.power_ethernet import check_power_ethernet
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = {
        'device': check_device,
        'entity': check_entity,
        'entitySensor': check_entity_sensor,
        'interface': check_interface,
        'ipAddress': check_ip_address,
        'ipForward': check_ip_forward,
        'powerEthernet': check_power_ethernet,
        'process': check_process,
        'processor': check_processor,
        'storage': check_storage,
        'system': check_system,
        'tcpConnection': check_tcp_connection,
        'tcpListener': check_tcp_listener,
    }

    probe = Probe("snmp", version, checks)

    probe.start()
