import crypt
import hashlib
import re
import os
from base64 import b64encode, b64decode
from hmac import compare_digest as secure_equals

from .exceptions import *

# https://tools.ietf.org/id/draft-stroeder-hashed-userpassword-values-01.html
# laurelin will always hash passwords being stored in the backend, and will always be stored
# using the `prefix b64-hashandsalt` syntax in the above document, i.e. stored passwords will
# never be cleartext


## Common utilities


class PasswordScheme(object):
    def __init__(self, scheme: str):
        self._name = scheme.upper()
        try:
            self.hasher, self.is_salted = _scheme_to_hasher(scheme)
            self.kind = '_hash'
        except AuthMethodNotSupportedError:
            if scheme.upper() in _crypt_names:
                self.kind = '_crypt'
            else:
                raise

    def __str__(self):
        return self._name


def _scheme_to_hasher(scheme):
    # convert scheme to candidate algorithm name
    algo = scheme.lower()
    if algo.endswith('sha'):
        algo += '1'

    # Find the algorithm and if salted
    salted = False
    try:
        # check for non-salted scheme
        hasher = hashlib.new(algo)
    except ValueError:
        if algo.startswith('s'):
            # probably a salted scheme
            try:
                hasher = hashlib.new(algo[1:])
                salted = True
            except ValueError:
                raise AuthMethodNotSupportedError(f'Unsupported password hash scheme "{scheme}"')
        else:
            raise AuthMethodNotSupportedError(f'Unsupported password hash scheme "{scheme}"')

    return hasher, salted


_crypt_names = [method.name for method in crypt.methods]


## Check functions for comparing cleartext input password to stored data


def _check_hashed(scheme, input_clear_password: str, pw_data: bytes):
    input_clear_password = input_clear_password.encode()
    if scheme.is_salted:
        # run empty digest to get the length of the hash for the algorithm
        hash_length = len(scheme.hasher.digest())
        stored_hash = pw_data[:hash_length]

        # hash the input password with stored salt
        scheme.hasher.update(input_clear_password)
        salt = pw_data[hash_length:]
        scheme.hasher.update(salt)
        input_hashed = scheme.hasher.digest()
    else:
        # no salt, only hash
        stored_hash = pw_data

        # hash the input password
        scheme.hasher.update(input_clear_password)
        input_hashed = scheme.hasher.digest()

    return secure_equals(stored_hash, input_hashed)


def _check_crypted(input_clear_password: str, pw_data: bytes):
    crypted_pw = pw_data.decode('utf-8')
    input_crypted = crypt.crypt(input_clear_password, crypted_pw)
    return secure_equals(input_crypted, crypted_pw)


def check_password(input_clear_password: str, stored_pw: str):
    """Check if a cleartext password matches a stored hashed/base64 encoded password with scheme identifier"""

    # Extract hash scheme and hash/salt
    m = re.match(r'^\{([a-zA-Z0-9_]+)\}(.+)', stored_pw)
    if not m:
        raise InternalError('hashed_password is not valid syntax')
    scheme = PasswordScheme(m.group(1))
    pw_data = b64decode(m.group(2))

    if scheme.kind == '_hash':
        _check_hashed(scheme, input_clear_password, pw_data)
    elif scheme.kind == '_crypt':
        _check_crypted(input_clear_password, pw_data)
    else:
        raise InternalError('Unknown scheme kind')


## Functions to prepare a password for storage


def _hash_password(scheme: PasswordScheme, input_clear_password: str):
    scheme.hasher.update(input_clear_password.encode())
    if scheme.is_salted:
        salt = os.urandom(16)
        scheme.hasher.update(salt)
    else:
        salt = b''
    input_hashed = scheme.hasher.digest()
    hash_and_salt = b64encode(input_hashed + salt).decode('utf-8')
    return f'{{{scheme}}}{hash_and_salt}'


def _crypt_password(input_clear_password: str, scheme):
    method = getattr(crypt, 'METHOD_' + scheme)
    salt = crypt.mksalt(method)
    crypted_pw = crypt.crypt(input_clear_password, salt).encode()
    encoded_pw = b64encode(crypted_pw).decode('utf-8')
    return '{' + scheme.upper() + '}' + encoded_pw


def prepare_password(input_clear_password: str, scheme='SSHA3_512'):
    scheme = PasswordScheme(scheme)
    if scheme.kind == '_hash':
        return _hash_password(scheme, input_clear_password)
    elif scheme.kind == '_crypt':
        return _crypt_password(input_clear_password, str(scheme))
    else:
        raise InternalError('Unknown scheme kind')
