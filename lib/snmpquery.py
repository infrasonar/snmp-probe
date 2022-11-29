import logging
from asyncsnmplib.client import Snmp, SnmpV1, SnmpV3
from asyncsnmplib.exceptions import SnmpNoConnection, SnmpNoAuthParams
from asyncsnmplib.mib.utils import on_result
from libprobe.asset import Asset
from libprobe.exceptions import CheckException


async def snmpquery(
        asset: Asset,
        asset_config: dict,
        check_config: dict,
        queries: dict):
    address = check_config.get('address')
    if address is None:
        address = asset.name

    # TODO in asset_config aparte sectie voor credentials (snmpv3)?
    version = asset_config.get('version', '2c')
    community = asset_config.get('community', 'public')
    if version == '2c':
        cl = Snmp(
            host=address,
            community=community,
        )
    elif version == '3':
        cred = asset_config['credentials']
        if cred is None:
            logging.warning(f'missing credentials for {address}')
            return
        try:
            cl = SnmpV3(
                host=address,
                **cred,
            )
        except Exception as e:
            logging.warning(f'invalid snmpv3 client config for {address}')
            return
    elif version == '1':
        cl = SnmpV1(
            host=address,
            community=community,
        )
    else:
        logging.warning(f'unsupported snmpVersion {version}')
        return

    try:
        await cl.connect()
    except SnmpNoConnection:
        logging.error(f'unable to connect to {asset.id} {address}')
        return
    except SnmpNoAuthParams:
        logging.error(f'unable to set auth params for {asset.id} {address}')
        cl.close()
        return

    results = {}
    try:
        for oid in queries:
            result = await cl.walk(oid)
            try:
                name, result = on_result(oid, result)
            except Exception as e:
                raise CheckException(
                    f'Check result error: {e.__class__.__name__}: {e}')
            else:
                results[name] = result
    except CheckException:
        raise
    except Exception as e:
        raise CheckException(f'Check error: {e.__class__.__name__}: {e}')
    else:
        return results
    finally:
        cl.close()
