import ipaddress
import time
from typing import Union, Any
from .exceptions import ParseKeyException


class InterfaceLookup:
    _lk = {}
    _MAX_AGE = 900

    @classmethod
    def get(cls, asset_id: int) -> Union[dict[int, dict[str, Any]], None]:
        ts, data = cls._lk.get(asset_id, (None, None))
        if ts is None or time.time() - ts > cls._MAX_AGE:
            return
        return data

    @classmethod
    def set(cls, asset_id: int, rows: list) -> dict[int, dict[str, Any]]:
        data = {i['Index']: i for i in rows}
        cls._lk[asset_id] = (time.time(), data)
        return data


def addr_ipv4(octets):
    n = octets[0]
    if len(octets) == n + 1 == 5:
        # IPv4 in format like 192,168,0,0
        return '.'.join(map(str, octets[1:5]))
    elif len(octets) == 4:
        # Assume just the IP without explicit length
        # (we found this scenario with IP camera's)
        return '.'.join(map(str, octets))

    # Assume string format:
    def _chr(x):
        assert 46 <= x < 58  # IPv4
        return chr(x)

    return ''.join(_chr(x) for x in octets[1:n + 1])


def addr_ipv4z(octets):
    # Zone info will just be ignored
    n = octets[0]
    assert len(octets) == n + 1 == 9
    return '.'.join(map(str, octets[1:5]))


def addr_ipv6(octets):
    n = octets[0]
    if len(octets) == n + 1 == 17:
        nr = sum(o * (2 ** ((16 - i - 1) * 8))
                 for i, o in enumerate(octets[1:17]))
        return str(ipaddress.IPv6Address(nr))

    # Assume string format:
    def _chr(x):
        assert 46 <= x < 96  # IPv6
        return chr(x)

    return ''.join(_chr(x) for x in octets[1:n + 1])


def addr_ipv6z(octets):
    # Zone info will just be ignored
    n = octets[0]
    assert len(octets) == n + 1 == 21
    nr = sum(o * (2 ** ((16 - i - 1) * 8)) for i, o in enumerate(octets[1:17]))
    return str(ipaddress.IPv6Address(nr))


def addr_netmask(addr, n):
    try:
        return str(ipaddress.ip_network(f'{addr}/{n}', strict=False).netmask)
    except ValueError:
        return None


def addr_dns(octets):
    n = octets[0]
    assert len(octets) == n + 1
    return ''.join(map(chr, octets[1:1 + n]))


ADDRESS_TP = {
    0: ('unknown', lambda v: None),
    1: ('ipv4', addr_ipv4),
    2: ('ipv6', addr_ipv6),
    3: ('ipv4z', addr_ipv4z),
    4: ('ipv6z', addr_ipv6z),
    16: ('dns', addr_dns),
}


def ip_mib_address(key, item):
    # some devices return ipAddressAddrType and ipAddressAddr as
    # values, these may be imporperly formatted or null,
    # so we derive these from the key like we do with the other checks
    # (tcpConnections, tcpListeners)
    orig_key = key
    key = tuple(map(int, key.split('.')))
    try:
        local_typ = key[0]
        local_typ_name, local_typ_func = ADDRESS_TP[local_typ]
        local_addr = local_typ_func(key[1:])
    except Exception:
        # Some devices (noticed with APC) have an invalid `2` in front
        # of the OID but aren't IPv6. For example: 2.1.4.192.168.0.1
        # We tried stripping the `2` but other metrics are missing as well.
        if not (
            isinstance(item.get('Addr'), str) and
            isinstance(item.get('AddrType'), str)
        ):
            raise ParseKeyException(orig_key)
    else:
        item['AddrType'] = local_typ_name
        item['Addr'] = local_addr

    # when value is 0.0 or 1.1 ignore
    # some devices don't follow mib's syntax and return None
    # in case of an unparseable int instead of a RowPointer (oid)
    if 'Prefix' in item and item['Prefix'] not in (
        'zeroDotZero',  # oid 0.0
        'internet',  # oid 1.1
        None,
    ):
        prefix_key = None
        n = 10  # length of 1.3.6.1.2.1.4.32.1.5 IP-MIB::ipAddressPrefixOrigin
        try:
            prefix_key = tuple(
                map(int, item['Prefix'].split('.')[n:]))
            prefix_ifindex = prefix_key[0]
            prefix_typ = prefix_key[1]
            prefix_typ_name, prefix_typ_func = ADDRESS_TP[prefix_typ]
            prefix_addr = prefix_typ_func(prefix_key[2:-1])
            prefix_len = prefix_key[-1]
        except Exception:
            raise Exception('Unable to derive address-prefix info from '
                            f'oid-part {prefix_key}')
        item['PrefixIfIndex'] = prefix_ifindex
        item['PrefixType'] = prefix_typ_name
        item['PrefixAddr'] = prefix_addr
        item['PrefixLength'] = prefix_len
        netmask = addr_netmask(prefix_addr, prefix_len)
        if netmask is not None:
            item['NetMask'] = netmask

    return item


def tcp_mib_connection(key, item):
    key = tuple(map(int, key.split('.')))
    try:
        local_typ = key[0]
        local_typ_len = key[1]
        local_typ_name, local_typ_func = ADDRESS_TP[local_typ]
        local_addr = local_typ_func(key[1: 2 + local_typ_len])
        local_pt = key[2 + local_typ_len]
        remote_typ = key[3 + local_typ_len]
        remote_typ_len = key[4 + local_typ_len]
        remote_typ_name, remote_typ_func = ADDRESS_TP[remote_typ]
        remote_addr = remote_typ_func(key[-remote_typ_len - 2:-1])
        remote_pt = key[-1]
    except Exception:
        raise Exception(f'Unable to derive address info from oid-part {key}')

    item['LocalAddressType'] = local_typ_name
    item['LocalAddress'] = local_addr
    item['LocalPort'] = local_pt
    item['RemAddressType'] = remote_typ_name
    item['RemAddress'] = remote_addr
    item['RemPort'] = remote_pt
    return item


def tcp_mib_listener(key, item):
    key = tuple(map(int, key.split('.')))
    try:
        local_typ = key[0]
        local_typ_name, local_typ_func = ADDRESS_TP[local_typ]
        local_addr = local_typ_func(key[1: -1])
        local_pt = key[-1]
    except Exception:
        raise Exception(f'Unable to derive address info from oid-part {key}')

    item['LocalAddressType'] = local_typ_name
    item['LocalAddress'] = local_addr
    item['LocalPort'] = local_pt
    return item
