from libprobe.probe import Probe
from lib.check.base import CheckBase
from lib.check.device import CheckDevice
from lib.check.entity import CheckEntity
from lib.check.interface import CheckInterface
from lib.check.ip import CheckIp
from lib.check.ip_address import CheckIpAddress
from lib.check.ip_forward import CheckIpForward
from lib.check.lldp import CheckLldp
from lib.check.power_ethernet import CheckPowerEthernet
from lib.check.process import CheckProcess
from lib.check.processor import CheckProcessor
from lib.check.sensor import CheckSensor
from lib.check.storage import CheckStorage
from lib.check.system import CheckSystem
from lib.check.tcp import CheckTcp
from lib.check.tcp_connection import CheckTcpConnection
from lib.check.tcp_listener import CheckTcpListener
from lib.check.ucd import CheckUcd
from lib.check.udp import CheckUdp
from lib.version import __version__ as version


if __name__ == '__main__':
    checks = (
        CheckBase,
        CheckDevice,
        CheckEntity,
        CheckInterface,
        CheckIp,
        CheckIpAddress,
        CheckIpForward,
        CheckLldp,
        CheckPowerEthernet,
        CheckProcess,
        CheckProcessor,
        CheckSensor,
        CheckStorage,
        CheckSystem,
        CheckTcp,
        CheckTcpConnection,
        CheckTcpListener,
        CheckUcd,
        CheckUdp,
    )

    probe = Probe("snmp", version, checks)

    probe.start()
