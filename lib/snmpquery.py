import logging
from asyncsnmplib.client import Snmp, SnmpV1, SnmpV3
from asyncsnmplib.exceptions import SnmpNoConnection, SnmpNoAuthParams
from asyncsnmplib.mib.utils import on_result
from libprobe.asset import Asset
from libprobe.exceptions import CheckException
from asyncsnmplib.v3.auth import AUTH_PROTO
from asyncsnmplib.v3.encr import PRIV_PROTO


def snmpv3_credentials(asset_config: dict):
    try:
        user_name = asset_config['user_name']
    except KeyError:
        raise Exception(f'missing `user_name`')

    auth_type = asset_config.get('auth_type', 'USM_AUTH_NONE')
    if auth_type != 'USM_AUTH_NONE':
        if auth_type not in AUTH_PROTO:
            raise Exception(f'invalid `auth_type`')

        try:
            auth_passwd = asset_config['auth_passwd']
        except KeyError:
            raise Exception(f'missing `auth_passwd`')

        priv_type = asset_config.get('priv_type', 'USM_PRIV_NONE')
        if priv_type != 'USM_PRIV_NONE':
            if priv_type not in PRIV_PROTO:
                raise Exception(f'invalid `priv_type`')

            try:
                priv_passwd = asset_config['priv_passwd']
            except KeyError:
                raise Exception(f'missing `priv_passwd`')

            return {
                'username': user_name,
                'auth_proto': auth_type,
                'auth_passwd': auth_passwd,
                'priv_proto': priv_type,
                'priv_passwd': priv_passwd,
            }
        else:
            return {
                'username': user_name,
                'auth_proto': auth_type,
                'auth_passwd': auth_passwd,
            }
    else:
        return {
            'username': user_name,
        }


async def snmpquery(
        asset: Asset,
        asset_config: dict,
        check_config: dict,
        queries: dict):
    address = check_config.get('address')
    if address is None:
        address = asset.name

    version = asset_config.get('version', '2c')
    community = asset_config.get('community', 'public')
    if version == '2c':
        cl = Snmp(
            host=address,
            community=community,
        )
    elif version == '3':
        try:
            cred = snmpv3_credentials(asset_config)
        except Exception as e:
            logging.warning(f'invalid snmpv3 credentials {asset}: {e}')
            return
        try:
            cl = SnmpV3(
                host=address,
                **cred,
            )
        except Exception as e:
            logging.warning(f'invalid snmpv3 client config {asset}: {e}')
            return
    elif version == '1':
        cl = SnmpV1(
            host=address,
            community=community,
        )
    else:
        logging.warning(f'unsupported snmp version {asset}: {version}')
        return

    try:
        await cl.connect()
    except SnmpNoConnection:
        logging.error(f'unable to connect to {asset}: {address}')
        return
    except SnmpNoAuthParams:
        logging.error(f'unable to set auth params {asset}')
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
