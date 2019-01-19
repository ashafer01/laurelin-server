import os.path

from collections import defaultdict
from glob import glob

import yaml

from laurelin.ldap import rfc4512
from laurelin.ldap.utils import CaseIgnoreDict, re_anchor

from .syntax import SyntaxRule
from .matching_rule import MatchingRule
from .attribute_type import AttributeType
from .object_class import ObjectClass, ExtensibleObjectClass
from ..exceptions import *

# TODO make this an env var / CLI startup parameter
_schema_dir = os.path.expanduser('~/etc/laurelin/server/schema.d')


kind_factories = {
    'syntax_rules': SyntaxRule,
    'matching_rules': MatchingRule,
    'attribute_types': AttributeType,
    'object_classes': ObjectClass,
}


def schema_element(kind, params):
    return kind_factories[kind](params)


def _element_getter(key):
    def get_element(self, ident):
        if ident[0].isdigit():
            dct = self._oids
        else:
            dct = self._schema[key]
        return dct[ident]
    return get_element


class Schema(object):
    def __init__(self):
        self._schema = defaultdict(CaseIgnoreDict)
        self._oids = {}

        # These shall be the only 3 hard coded schema elements to enable special-casing extensibleObject
        self._schema['syntax_rules']['oid'] = SyntaxRule({
            'oid': '1.3.6.1.4.1.1466.115.121.1.38',
            'desc': 'OID',
            'name': 'oid',
            'regex': re_anchor(rfc4512.oid),
        })
        self._schema['attribute_type']['objectClass'] = AttributeType({
            'equality_rule': 'objectIdentifierMatch',
            'name': 'objectClass',
            'desc': 'object class',
            'oid': '2.5.4.0',
            'syntax': '1.3.6.1.4.1.1466.115.121.1.38'
        })
        self._schema['object_classes']['top'] = ObjectClass({
            'name': 'top',
            'desc': 'top',
            'oid': '2.5.6.0',
            'required_attributes': ['objectClass'],
            'type': 'abstract'
        })
        self._schema['object_classes']['extensibleObject'] = ExtensibleObjectClass()

    def load(self):
        self.load_dir(_schema_dir)

    def load_dir(self, schema_dir):
        if schema_dir is None:
            schema_dir = _schema_dir

        files = glob(os.path.join(schema_dir, '*.yaml'))
        files += glob(os.path.join(schema_dir, '*.yml'))
        if not files:
            raise LDAPError(f'No schema files found in {schema_dir}')

        files.sort()
        for fn in files:
            self.load_file(fn)

    def load_file(self, fn):
        with open(fn) as f:
            data = yaml.safe_load(f)
            self.load_dict(data)

    def load_dict(self, data):
        for kind, elements in data.items():
            for name, params in elements.items():
                params.setdefault('name', name)
                params.setdefault('desc', params['name'])
                element = schema_element(kind, params)
                self._schema[kind][name] = element
                if 'oid' in params:
                    self._oids[params['oid']] = element

    def resolve(self):
        """Resolve all inheritance"""
        try:
            for key in 'object_classes', 'attribute_types':
                for obj in self._schema[key].values():
                    obj.resolve()
        except KeyError:
            raise InvalidSchemaError('missing inherited schema element')

    get_attribute_type = _element_getter('attribute_types')
    get_object_class = _element_getter('object_classes')
    get_matching_rule = _element_getter('matching_rules')
    get_syntax_rule = _element_getter('syntax_rules')


schema = Schema()


class BaseSchemaElement(object):
    def __init__(self, params):
        self._params = params

    def __getitem__(self, item):
        return self._params[item]

    def __contains__(self, item):
        return item in self._params
