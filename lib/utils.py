import ipaddress


def addr_ipv4(octets):
    n = octets[0]
    assert len(octets) == n + 1 == 5
    return '.'.join(map(str, octets[1:5]))


def addr_ipv4z(octets):
    # Zone info will just be ignored
    n = octets[0]
    assert len(octets) == n + 1 == 9
    return '.'.join(map(str, octets[1:5]))


def addr_ipv6(octets):
    n = octets[0]
    assert len(octets) == n + 1 == 17
    nr = sum(o * (2 ** ((16 - i - 1) * 8)) for i, o in enumerate(octets[1:17]))
    return str(ipaddress.IPv6Address(nr))


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
    0: ('unknown', lambda v: ''),
    1: ('ipv4', addr_ipv4),
    2: ('ipv6', addr_ipv6),
    3: ('ipv4z', addr_ipv4z),
    4: ('ipv6z', addr_ipv6z),
    16: ('dns', addr_dns),
}


def ip_mib_address(key, item):
    key = tuple(map(int, key.split('.')))
    try:
        local_typ = key[0]
        local_typ_name, local_typ_func = ADDRESS_TP[local_typ]
        local_addr = local_typ_func(key[1:])
    except Exception:
        raise Exception(f'Unable to derive address info from oid-part {key}')

    item['ipAddressAddrType'] = local_typ_name
    item['ipAddressAddr'] = local_addr

    # when value is 0.0 or 1.1 ignore
    # some devices don't follow mib's syntax and return None
    # in case of an unparseable int instead of a RowPointer (oid)
    if 'ipAddressPrefix' in item and item['ipAddressPrefix'] not in (
        'zeroDotZero',  # oid 0.0
        'internet',  # oid 1.1
        None,
    ):
        n = 10  # length of 1.3.6.1.2.1.4.32.1.5 IP-MIB::ipAddressPrefixOrigin
        try:
            prefix_key = tuple(
                map(int, item['ipAddressPrefix'].split('.')[n:]))
            prefix_ifindex = prefix_key[0]
            prefix_typ = prefix_key[1]
            prefix_typ_name, prefix_typ_func = ADDRESS_TP[prefix_typ]
            prefix_addr = prefix_typ_func(prefix_key[2:-1])
            prefix_len = prefix_key[-1]
        except Exception:
            raise Exception('Unable to derive address-prefix info from '
                            f'oid-part {prefix_key}')
        netmask = addr_netmask(prefix_addr, prefix_len)
        item['ipAddressPrefixIfIndex'] = prefix_ifindex
        item['ipAddressPrefixType'] = prefix_typ_name
        item['ipAddressPrefixAddr'] = prefix_addr
        item['ipAddressPrefixLength'] = prefix_len
        item['ipAddressNetMask'] = netmask

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

    item['tcpConnectionLocalAddressType'] = local_typ_name
    item['tcpConnectionLocalAddress'] = local_addr
    item['tcpConnectionLocalPort'] = local_pt
    item['tcpConnectionRemAddressType'] = remote_typ_name
    item['tcpConnectionRemAddress'] = remote_addr
    item['tcpConnectionRemPort'] = remote_pt
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

    item['tcpListenerLocalAddressType'] = local_typ_name
    item['tcpListenerLocalAddress'] = local_addr
    item['tcpListenerLocalPort'] = local_pt
    return item
