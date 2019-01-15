import os.path

from collections import defaultdict
from glob import glob

import yaml

from laurelin.ldap.utils import CaseIgnoreDict

from .exceptions import LDAPError

# TODO make this an env var / CLI startup parameter
_schema_dir = os.path.expanduser('~/etc/laurelin/server/schema.d')


def _element_getter(key, cls):
    def get_element(self, ident):
        if ident[0].isdigit():
            dct = self._oids
        else:
            dct = self._schema[key]
        o = dct[ident]
        if isinstance(o, dict):
            dct[ident] = cls(o)
        return dct[ident]
    return get_element


class SchemaElement:
    def __init__(self, params):
        self._params = params

    def __getattr__(self, item):
        return self._params[item]

    def __getitem__(self, item):
        return self._params[item]


class AttributeType(SchemaElement):
    pass


class ObjectClass(SchemaElement):
    pass


class MatchingRule(SchemaElement):
    pass


class SyntaxRule(SchemaElement):
    pass


class Schema:
    def __init__(self):
        self._schema = defaultdict(CaseIgnoreDict)
        self._oids = {}

    def load(self):
        self.load_dir(_schema_dir)

    def load_dir(self, schema_dir):
        if schema_dir is None:
            schema_dir = _schema_dir

        files = glob(os.path.join(schema_dir, '*.yaml'), recursive=True)
        files += glob(os.path.join(schema_dir, '*.yml'), recursive=True)
        if not files:
            raise LDAPError('No schema files found')

        files.sort()
        for fn in files:
            self.load_file(fn)

    def load_file(self, fn):
        with open(fn) as f:
            data = yaml.safe_load(f)
            self.load_dict(data)

    def load_dict(self, data):
        for kind, elements in data.items():
            for name, params in elements:
                self._schema[kind][name] = params
                if 'oid' in params:
                    self._oids[params['oid']] = params

    get_attribute_type = _element_getter('attribute_types', AttributeType)
    get_object_class = _element_getter('object_classes', ObjectClass)
    get_matching_rule = _element_getter('matching_rules', MatchingRule)
    get_syntax_rule = _element_getter('syntax_rules', SyntaxRule)
