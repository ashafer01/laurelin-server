import os.path

from collections import defaultdict
from glob import glob

import yaml

from laurelin.ldap import rfc4512
from laurelin.ldap.utils import CaseIgnoreDict, re_anchor

from .exceptions import LDAPError, SchemaValidationError

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

    def __getitem__(self, item):
        return self._params[item]


class AttributeType(SchemaElement):
    def __init__(self, params):
        if 'usage' not in params:
            params['usage'] = 'userApplications'
        SchemaElement.__init__(self, params)


class ObjectClass(SchemaElement):
    def __init__(self, params):
        SchemaElement.__init__(self, params)
        self.required_attrs = {attr.lower() for attr in self['required_attributes']}
        self.allowed_attrs = {attr.lower() for attr in self['allowed_attributes']}

    def merge(self, object_class):
        """Combine another ObjectClass with this one, returning a new ObjectClass"""

    def validate(self, attrs: dict):
        """Ensure a dictionary of attributes conforms to this ObjectClass"""
        attr_types_set = {attr.lower() for attr in attrs.keys()}

        missing_required = self.required_attrs - attr_types_set
        if missing_required:
            missing_required = ', '.join(missing_required)
            raise SchemaValidationError(f'Missing required attributes: {missing_required}')

        not_required = attr_types_set - self.required_attrs
        not_allowed = not_required - self.allowed_attrs
        if not_allowed:
            not_allowed = ', '.join(not_allowed)
            raise SchemaValidationError(f'Attribute types are not allowed: {not_allowed}')

        # TODO validate values against AttributeTypes


class ExtensibleObjectClass(SchemaElement):
    def __init__(self):
        SchemaElement.__init__(self, {
            'oid': '1.3.6.1.4.1.1466.101.120.111',
            'name': 'extensibleObject',
            'inherits': 'top',
            'type': 'auxiliary',
        })

    @staticmethod
    def validate(attrs: dict):
        for attr in attrs.keys():
            if attr['usage'] != 'userApplications':
                raise SchemaValidationError('Non-user attribute on extensibleObject')

        # TODO validate values against AttributeTypes


class MatchingRule(SchemaElement):
    pass


class SyntaxRule(SchemaElement):
    pass


class Schema:
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
            'oid': '2.5.4.0',
            'syntax': '1.3.6.1.4.1.1466.115.121.1.38'
        })
        self._schema['object_classes']['top'] = ObjectClass({
            'name': 'top',
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
            for name, params in elements:
                self._schema[kind][name] = params
                if 'oid' in params:
                    self._oids[params['oid']] = params

    get_attribute_type = _element_getter('attribute_types', AttributeType)
    get_object_class = _element_getter('object_classes', ObjectClass)
    get_matching_rule = _element_getter('matching_rules', MatchingRule)
    get_syntax_rule = _element_getter('syntax_rules', SyntaxRule)
