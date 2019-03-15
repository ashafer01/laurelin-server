from .exceptions import *
from .schema import get_schema

from laurelin.ldap.protoutils import split_unescaped


class RDN(frozenset):
    def __init__(self, *args):
        frozenset.__init__(*args)
        self._str = None

    def __str__(self):
        if self._str is None:
            self._str = '+'.join(['='.join(ava) for ava in self])
        return self._str

    def __repr__(self):
        return f'RDN({repr(str(self))})'


class DN(list):
    def __init__(self, original=None):
        list.__init__(self)
        self._original = original
        self._stringified = None

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
        return f'DN({repr(str(self))})'

    def __getitem__(self, item):
        if isinstance(item, slice):
            ndn = DN()
            ndn.extend(list.__getitem__(self, item))
            return ndn
        else:
            return list.__getitem__(self, item)


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
            raise InvalidDNError('Invalid RDN - no equals sign or equals sign needs escaping')
        try:
            val = get_schema().get_attribute_type(attr).prepare_value(val)
        except UndefinedSchemaElementError:
            raise InvalidDNError(f'Invalid RDN - attribute type {attr} does not exist')
        except NeededRuleError:
            raise InvalidDNError(f'Invalid RDN - attribute type {attr} cannot be used for an RDN attribute because a '
                                 f'matching rule is not available to compare values')
        tpl_avas.append((attr.lower(), val))
    return RDN(tpl_avas)


def parse_dn(dn):
    if isinstance(dn, DN):
        return dn
    str_rdns = split_unescaped(dn, ',')
    dn = DN(dn)
    for rdn in str_rdns:
        dn.append(parse_rdn(rdn))
    return dn
