import logging
from asyncsnmplib.client import Snmp, SnmpV1, SnmpV3
from asyncsnmplib.exceptions import SnmpNoAuthParams
from asyncsnmplib.exceptions import SnmpNoConnection
from asyncsnmplib.mib.utils import on_result
from libprobe.exceptions import CheckException
from typing import Union, Tuple, Dict, List, Any


async def snmpquery(
    client: Union[Snmp, SnmpV1, SnmpV3],
    oids: Tuple[Tuple[int], ...]
) -> Dict[str, List[Dict[str, Any]]]:

    try:
        await client.connect()
    except SnmpNoConnection:
        raise
    except SnmpNoAuthParams:
        logging.warning('unable to connect: failed to set auth params')
        raise
    else:
        results = {}
        for oid in oids:
            result = await client.walk(oid)
            try:
                name, result = on_result(oid, result)
            except Exception as e:
                msg = str(e) or type(e).__name__
                raise CheckException(
                    f'Failed to parse result. Exception: {msg}')
            else:
                results[name] = result
        return results
    finally:
        # safe to close whatever the connection status is
        client.close()
