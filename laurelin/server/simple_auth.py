import re
from base64 import b64decode

import laurelin.ldap.exceptions
from laurelin.ldap import rfc4511, Scope, DerefAliases
from laurelin.ldap.filter import parse as parse_filter
from laurelin.ldap.utils import CaseIgnoreDict

from .config import Config
from .dit import DIT
from .exceptions import *
from .internal_client import InternalClient
from .simple_passwords import check_password
from .utils import optional_component


_main_filter = '(userPassword=*)'
_return_attrs = ['userPassword']


class LDAPStorage(object):
    """Utilizes standard userPassword attributes on objects in global DIT"""

    def __init__(self, auth_conf: Config, dit: DIT):
        self.client = InternalClient(dit)

        try:
            custom_filter = auth_conf['ldap_filter']
            self.filter = parse_filter(f'{_main_filter} AND {custom_filter}')
        except KeyError:
            self.filter = parse_filter(_main_filter)
        except laurelin.ldap.exceptions.LDAPError:
            raise ConfigError('ldap_filter is not a valid filter')

        try:
            deref_str = auth_conf['ldap_deref_aliases']
            self.deref = getattr(DerefAliases, deref_str)
        except KeyError:
            self.deref = DerefAliases.NEVER
        except AttributeError:
            raise ConfigError('Invalid value for ldap_deref_aliases')

        self.multi = auth_conf.get('ldap_multiple_passwords', False)

    async def authenticate(self, mapped_name: str, input_password: str):
        user_res = None
        async for res in self.client.search(mapped_name, Scope.BASE, fil=self.filter, deref_aliases=self.deref,
                                            attrs=_return_attrs):
                user_res = res
        if not user_res:
            raise AuthNameDoesNotExist()

        user_attrs = CaseIgnoreDict(user_res.attrs)
        try:
            pass_attr = user_attrs['userPassword']
        except KeyError:
            raise AuthFailure('No userPassword attribute on returned user object')

        if not self.multi and len(pass_attr) > 1:
            raise AuthFailure('Multiple userPassword values are present but ldap_multiple_passwords is False')

        for stored_pw in pass_attr:
            match = check_password(input_password, stored_pw)
            if match:
                return
        raise AuthInvalidCredentials()


class FlatFileStorage(object):
    """Stores credentials in a b64(user):password mapping in a local flat file"""
    def __init__(self, auth_conf: Config):
        self.filename = auth_conf['flat_filename']
        self.read_mode = auth_conf.get('flat_read_mode', 'startup')
        self.cred_map = {}
        if self.read_mode == 'startup':
            self.read_map()
        elif self.read_mode == 'auth':
            pass
        else:
            raise ConfigError(f'Invalid flat_read_mode {self.read_mode}')

    async def authenticate(self, mapped_name: str, input_password: str):
        if self.read_mode == 'auth':
            self.read_map()
        try:
            stored_pw = self.cred_map[mapped_name]
            match = check_password(input_password, stored_pw)
            if not match:
                raise AuthInvalidCredentials()
        except KeyError:
            raise AuthNameDoesNotExist()

    def read_map(self):
        self.cred_map.clear()
        with open(self.filename) as f:
            for line in f:
                b64_user, stored_pw = line.split(':')
                user = b64decode(b64_user)
                self.cred_map[user] = stored_pw


class SimpleAuthBackend(object):
    def __init__(self, auth_conf: Config, dit: DIT):
        self.conf = auth_conf
        self.dit = dit
        storage = auth_conf.get('storage', 'ldap')
        if storage == 'ldap':
            self.storage = LDAPStorage(auth_conf, dit)
        elif storage == 'flat':
            self.storage = FlatFileStorage(auth_conf)
        else:
            raise ConfigError(f'Unknown simple storage backend {storage}')

        self._maps = []
        for map_conf in auth_conf.get('name_maps', ()):
            self._maps.append((re.compile(map_conf['search']), map_conf['replace']))

    def map_auth_name(self, input_name):
        for pattern, replace in self._maps:
            if pattern.search(input_name):
                return pattern.sub(replace, input_name)
        return input_name

    async def authenticate(self, name: str, auth_choice: rfc4511.AuthenticationChoice):
        """Perform simple password authentication"""
        mapped_name = self.map_auth_name(name)
        auth_type = auth_choice.getName()
        if auth_type == 'simple':
            input_pw = str(auth_type.getComponent())
        elif auth_type == 'sasl':
            sasl_cred = auth_type.getComponent()
            input_pw = optional_component(sasl_cred, 'credentials', val_type=str)
            if input_pw is None:
                raise AuthFailure('No credentials value set in sasl auth request')
        else:
            raise AuthMethodNotSupportedError(f'Authentication type "{auth_type}" is not supported')
        await self.storage.authenticate(mapped_name, input_pw)
        return mapped_name
