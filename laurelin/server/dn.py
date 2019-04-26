from typing import Iterable

from .exceptions import *
from .schema import get_schema

from laurelin.ldap.protoutils import split_unescaped


class RDN(frozenset):
    def __str__(self):
        try:
            return self._str
        except AttributeError:
            self._str = '+'.join(['='.join(ava) for ava in self])
            return self._str

    def __repr__(self):
        try:
            return self._repr
        except AttributeError:
            self._repr = 'RDN([' + ', '.join([f'({repr(a)}, {repr(v)})' for a, v in self]) + '])'
            return self._repr


class DN(tuple):
    def __new__(cls, original=None, rdns: Iterable = None):
        if rdns:
            return tuple.__new__(DN, rdns)
        else:
            return tuple.__new__(DN)

    def __init__(self, original=None, rdns: Iterable = None):
        self._original = original
        self._stringified = None
        self._repr = None

    def _stringify(self):
        if self._stringified is None:
            self._stringified = ','.join([str(rdn) for rdn in self])
        return self._stringified

    def __str__(self):
        if self._original is not None:
            return self._original
        else:
            return self._stringify()

    def __repr__(self):
        if self._repr is None:
            rdns = ', '.join([repr(rdn) for rdn in self])
            self._repr = f'DN(original={repr(self._original)}, rdns=[{rdns}])'
        return self._repr

    def __getitem__(self, item):
        if isinstance(item, slice):
            return DN(rdns=tuple.__getitem__(self, item))
        else:
            return tuple.__getitem__(self, item)


def parse_rdn(rdn):
    if isinstance(rdn, RDN):
        return rdn
    if rdn == '':
        return RDN()
    str_avas = split_unescaped(rdn, '+')
    tpl_avas = []
    for ava in str_avas:
        try:
            attr, val = split_unescaped(ava, '=')
        except ValueError:
            raise InvalidDNError(f'Invalid RDN AVA {ava} - no equals sign or equals sign needs escaping')
        try:
            val = get_schema().get_attribute_type(attr).prepare_value(val)
        except UndefinedSchemaElementError:
            raise InvalidDNError(f'Invalid RDN AVA {ava} - attribute type {attr} does not exist')
        except NeededRuleError:
            raise InvalidDNError(f'Invalid RDN AVA {ava} - attribute type {attr} cannot be used for an RDN attribute '
                                 'because a matching rule is not available to compare values')
        tpl_avas.append((attr.lower(), val))
    return RDN(tpl_avas)


def parse_dn(dn):
    if isinstance(dn, DN):
        return dn
    str_rdns = split_unescaped(dn, ',')
    rdns = []
    for rdn in str_rdns:
        rdns.append(parse_rdn(rdn))
    return DN(dn, rdns)
