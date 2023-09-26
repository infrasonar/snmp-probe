import logging
from asyncsnmplib.client import Snmp, SnmpV1, SnmpV3
from asyncsnmplib.exceptions import SnmpException
from asyncsnmplib.exceptions import SnmpNoAuthParams
from asyncsnmplib.exceptions import SnmpNoConnection
from asyncsnmplib.mib.utils import on_result
from asyncsnmplib.v3.auth import AUTH_PROTO
from asyncsnmplib.v3.encr import PRIV_PROTO
from libprobe.asset import Asset


class InvalidCredentialsException(SnmpException):
    message = 'Invalid SNMP v3 credentials.'


class InvalidClientConfigException(SnmpException):
    message = 'Invalid SNMP v3 client configuration.'


class InvalidSnmpVersionException(SnmpException):
    message = 'Invalid SNMP version.'


class ParseResultException(SnmpException):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def snmpv3_credentials(asset_config: dict):
    try:
        user_name = asset_config['username']
    except KeyError:
        raise Exception(f'missing `username`')

    auth = asset_config.get('auth')
    if auth is not None:
        auth_type = auth.get('type', 'USM_AUTH_NONE')
        if auth_type != 'USM_AUTH_NONE':
            if auth_type not in AUTH_PROTO:
                raise Exception(f'invalid `auth.type`')

            try:
                auth_passwd = auth['password']
            except KeyError:
                raise Exception(f'missing `auth.password`')

            priv = asset_config.get('priv', {})
            priv_type = priv.get('type', 'USM_PRIV_NONE')
            if priv_type != 'USM_PRIV_NONE':
                if priv_type not in PRIV_PROTO:
                    raise Exception(f'invalid `priv.type`')

                try:
                    priv_passwd = priv['password']
                except KeyError:
                    raise Exception(f'missing `priv.password`')

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

    if version == '2c':
        community = asset_config.get('community', 'public')
        if isinstance(community, dict):
            community = community.get('secret')
        if not isinstance(community, str):
            raise TypeError('SNMP community must be a string.')
        cl = Snmp(
            host=address,
            community=community,
        )
    elif version == '3':
        try:
            cred = snmpv3_credentials(asset_config)
        except Exception as e:
            logging.warning(f'invalid snmpv3 credentials {asset}: {e}')
            raise InvalidCredentialsException
        try:
            cl = SnmpV3(
                host=address,
                **cred,
            )
        except Exception as e:
            logging.warning(f'invalid snmpv3 client config {asset}: {e}')
            raise InvalidClientConfigException
    elif version == '1':
        community = asset_config.get('community', 'public')
        if isinstance(community, dict):
            community = community.get('secret')
        if not isinstance(community, str):
            raise TypeError('SNMP community must be a string.')
        cl = SnmpV1(
            host=address,
            community=community,
        )
    else:
        logging.warning(f'unsupported snmp version {asset}: {version}')
        raise InvalidSnmpVersionException

    try:
        await cl.connect()
    except SnmpNoConnection:
        raise
    except SnmpNoAuthParams:
        logging.warning('unable to connect: failed to set auth params')
        raise
    else:
        results = {}
        try:
            for oid in queries:
                result = await cl.walk(oid)
                try:
                    name, result = on_result(oid, result)
                except Exception as e:
                    msg = str(e) or type(e).__name__
                    raise ParseResultException(
                        f'Failed to parse result. Exception: {msg}'
                    )
                else:
                    results[name] = result
        except Exception:
            raise
        else:
            return results
    finally:
        # safe to close whatever the connection status is
        cl.close()
