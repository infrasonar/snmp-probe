from asyncsnmplib.mib.mib_index import MIB_INDEX
from collections import Counter
from libprobe.asset import Asset
from libprobe.exceptions import CheckException
from ..snmpquery import snmpquery

QUERIES = (
    MIB_INDEX['IF-MIB']['ifEntry'],
    MIB_INDEX['IF-MIB']['ifXEntry'],
)


'''
ifSpeed OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
            "An estimate of the interface's current bandwidth in bits
            per second.  For interfaces which do not vary in bandwidth
            or for those where no accurate estimation can be made, this
            object should contain the nominal bandwidth.  If the
            bandwidth of the interface is greater than the maximum value
            reportable by this object then this object should report its
            maximum value (4,294,967,295) and ifHighSpeed must be used
            to report the interace's speed.  For a sub-layer which has
            no concept of bandwidth, this object should be zero."
    ::= { ifEntry 5 }

ifHighSpeed OBJECT-TYPE
    SYNTAX      Gauge32
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION
            "An estimate of the interface's current bandwidth in units
            of 1,000,000 bits per second.  If this object reports a
            value of `n' then the speed of the interface is somewhere in
            the range of `n-500,000' to `n+499,999'.  For interfaces
            which do not vary in bandwidth or for those where no
            accurate estimation can be made, this object should contain
            the nominal bandwidth.  For a sub-layer which has no concept
            of bandwidth, this object should be zero."
    ::= { ifXEntry 15 }
'''


_64_BIT_COUNTERS = (
    'HCInOctets',
    'HCInUcastPkts',
    'HCInMulticastPkts',
    'HCInBroadcastPkts',
    'HCOutOctets',
    'HCOutUcastPkts',
    'HCOutMulticastPkts',
    'HCOutBroadcastPkts',
)

ExcludedIfTypes = (
    'ieee80211',
    'l3ipvlan',
    'l2vlan',
)

ExcludedIfDescStartsWith = (
    'veth',
    'lo',
    'nu',
    'vnet',
    'virbr',
)

ExcludedIfDescContains = (
    'vif',
    'stackport',
    'internal-data',
    'cplane'
)

# Address and prefixes matching these prefixes will be absolutely filtered
ReservedAddresses = (
    '00:00:01:00:00:01',    # Problematic XEROX CORPORATION MACs
    '00:00:01',             # Cisco ASA virtual MACs
    '01:00:01',
    '00:01:00:00:00:01',
    '00:08:e3',             # Cisco unicast
    '00:21:00:00:00:22',
    '00:13:00:00:00:14',
    '00:0f:b7:48:48',
    '00:16:00:00:00:16',
    '00:00:15:00:00:00',
    '00:15:00:00:00:15',
    '00:14:00:00:00:14',
    '00:14:00:00:00:15',
    '00:01:00:00:00:01',
    '00:21:00:00:00:21',
    '00:21:00:00:00:22',
    '7a:77:00:00:00:0',
    '00:00:03:00:00:00',
    '00:00:05:00:00:00',
    '00:08:e3:ff:fc:28',   # Problematic Cisco MACs
    '00:08:e3:ff:fd:90',
    '02:00:4c:4f:4f:50',
    '02:50:f2:00:00:01',
    '00:25:b5:00:00:0f',
    '00:25:b5:00:00:1f',
    '00:18:18:16',
    '12:00:00:00:00:00',
    '54:10:ec',            # Microchip
    '00:90:fa',            # Emulex
    'cc:4e:24',            # PCS
    '00:90:8f',            # Audio codes
    '38:90:a5:be',         # Threat Defense
    'b4:0c:25:e',          # Palo Alto Firewall HA
    '00:1b:17:00',
    'ba:db:ad',            # Palo Alto VMware interface
    '00:a0:c9:00:00:00',   # Firepower
    '00:13:00:00:00:13',   # Problematic LLDP chassis ID
    '00:00:00',            # ARP
    '01:00:00:00:00',
    '01:00:5e',            # Used for IPV4 Multicast and MLPS Multicast
    '33:33',               # Reserved for IPV6 Multicast
    '02:00:4c:4f:4f:50',   # Microsoft Loopback adapter`
    '20:41:53:59:4e:ff',   # RAS
    '00:22:bd:f8:19:ff',   # Cisco ACI
    '00:0b:ca:fe:00:00',   # Avaya/Xen
    '02:00:00',            # Common default
    '02:00:01',
    '00:00:03',            # Problematic Cisco ASA mac
    '00:07:b4:00',         # GLBP
    '00:09:0f:09',         # Fortinet HA
    '00:10:db:ff:10',      # Internal interfaces for Juniper
    '02:42:ac:11',         # Docker
    '00:ff:c2:f3:cb:94',   # Windows
    '1e:8e:39:50:50:05:05:69:00',  # VMware PVSCSI Controller
    'c8:4f:86:fc:00',      # Sophos virutal HA MAC
    '02:0f:00:0b:98',      # Sophos virutal HA MAC
)


async def check_interface(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    counts = Counter()
    itms = state_data.get('if', [])
    if_x_entry = {i.pop('name'): i for i in state_data.pop('ifX', [])}
    for item in itms:
        key = item['name']
        if item.get('Type') in ExcludedIfTypes:
            continue
        mac = item.get('PhysAddress')
        if isinstance(mac, str) and any(
                mac.startswith(e) for e in ReservedAddresses):
            continue
        try:
            name = item['Descr']
        except KeyError:
            raise CheckException('Missing required ifDesc OID for interface')
        if isinstance(name, str) and (
            any(name.startswith(e) for e in ExcludedIfDescStartsWith) or
                any(e in name for e in ExcludedIfDescContains)):
            continue
        idx = counts[name]
        counts[name] += 1
        item['name'] = f'{name}_{idx}' if idx else name

        try:
            item.update(if_x_entry[key])
        except KeyError:
            continue

        for _64_bit_name in _64_BIT_COUNTERS:
            if _64_bit_name in item:
                _32_bit_name = _64_bit_name[2:]
                item[_32_bit_name] = item.pop(_64_bit_name)

        if 'Speed' in item and 'HighSpeed' in item:
            # max value for this metric, shown if value is overloading
            if (item['Speed'] == 4294967295 and
                    item['HighSpeed'] != 4294):
                # ifspeed is in bits, ifHighSpeed in MBits.
                item['Speed'] = item['HighSpeed'] * 1000000

    return {
        'interface': itms
    }
