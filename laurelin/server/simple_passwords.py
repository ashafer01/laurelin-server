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


def _hash_scheme(scheme):
    # convert scheme to candidate algorithm name
    algo = scheme.lower()
    if algo.endswith('sha'):
        algo += '1'

    # Find the algorithm and if salted
    try:
        # check for non-salted scheme
        hasher = hashlib.new(algo)
        salted = False
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


class PasswordScheme(object):
    def __init__(self, scheme: str):
        self._name = scheme.upper()
        try:
            self.hasher, self.is_salted = _hash_scheme(scheme)
            self.check = self._check_hashed
            self.prepare = self._hash_password
        except AuthMethodNotSupportedError:
            if scheme.upper() in _crypt_names:
                self.check = self._check_crypted
                self.prepare = self._crypt_password
            else:
                raise

    def __str__(self):
        return self._name

    def _check_hashed(self, input_clear_password: str, pw_data: bytes):
        input_clear_password = input_clear_password.encode()
        if self.is_salted:
            # run empty digest to get the length of the hash for the algorithm
            hash_length = len(self.hasher.digest())
            stored_hash = pw_data[:hash_length]

            # hash the input password with stored salt
            self.hasher.update(input_clear_password)
            salt = pw_data[hash_length:]
            self.hasher.update(salt)
            input_hashed = self.hasher.digest()
        else:
            # no salt, only hash
            stored_hash = pw_data

            # hash the input password
            self.hasher.update(input_clear_password)
            input_hashed = self.hasher.digest()

        return secure_equals(stored_hash, input_hashed)

    @staticmethod
    def _check_crypted(input_clear_password: str, pw_data: bytes):
        crypted_pw = pw_data.decode('utf-8')
        input_crypted = crypt.crypt(input_clear_password, crypted_pw)
        return secure_equals(input_crypted, crypted_pw)

    def _hash_password(self, input_clear_password: str):
        self.hasher.update(input_clear_password.encode())
        if self.is_salted:
            salt = os.urandom(16)
            self.hasher.update(salt)
        else:
            salt = b''
        input_hashed = self.hasher.digest()
        hash_and_salt = b64encode(input_hashed + salt).decode('utf-8')
        return f'{{{self}}}{hash_and_salt}'

    def _crypt_password(self, input_clear_password: str):
        scheme = str(self)
        method = getattr(crypt, 'METHOD_' + scheme)
        salt = crypt.mksalt(method)
        crypted_pw = crypt.crypt(input_clear_password, salt).encode()
        encoded_pw = b64encode(crypted_pw).decode('utf-8')
        return '{' + scheme.upper() + '}' + encoded_pw


def check_password(input_clear_password: str, stored_pw: str):
    """Check if a cleartext password matches a stored password with scheme identifier"""

    # Extract hash scheme and hash/salt
    m = re.match(r'^\{([a-zA-Z0-9_]+)\}(.+)', stored_pw)
    if not m:
        raise InternalError('hashed_password is not valid syntax')
    scheme = PasswordScheme(m.group(1))
    pw_data = b64decode(m.group(2))

    return scheme.check(input_clear_password, pw_data)


def prepare_password(input_clear_password: str, scheme='SSHA3_512'):
    """Produce a hashed/crypted + encoded password with scheme identifier, ready for backend storage"""
    scheme = PasswordScheme(scheme)
    return scheme.prepare(input_clear_password)
