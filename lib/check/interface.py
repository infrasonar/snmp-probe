from asyncsnmplib.mib.mib_index import MIB_INDEX
from collections import Counter
from libprobe.asset import Asset
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


async def check_interface(
        asset: Asset,
        asset_config: dict,
        check_config: dict):

    state_data = await snmpquery(asset, asset_config, check_config, QUERIES)

    counts = Counter()
    itms = state_data.get('if', [])
    if_x_entry = {i['name']: i for i in state_data.pop('ifX', [])}
    for item in itms:
        key = item['name']
        name = item['Descr']
        idx = counts[name]
        counts[name] += 1
        item['name'] = f'{name}_{idx}' if idx else name

        try:
            item.update(if_x_entry[key])
        except KeyError:
            continue

        if 'HCInOctets' in item:
            item['InOctets'] = item.pop('HCInOctets')
        if 'HCOutOctets' in item:
            item['OutOctets'] = item.pop('HCOutOctets')

        if 'Speed' in item and 'HighSpeed' in item:
            # max value for this metric, shown if value is overloading
            if (item['Speed'] == 4294967295 and
                    item['HighSpeed'] != 4294):
                # ifspeed is in bits, ifHighSpeed in MBits.
                item['Speed'] = item['HighSpeed'] * 1000000

    return {
        'interface': itms
    }
