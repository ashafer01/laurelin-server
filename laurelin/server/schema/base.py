import os.path

from collections import defaultdict
from glob import glob
from importlib import import_module
from pkg_resources import resource_stream
from warnings import warn

import yaml

from laurelin.ldap import rfc4512
from laurelin.ldap.utils import CaseIgnoreDict, re_anchor

from ..exceptions import *

# TODO make this an env var / CLI startup parameter
_schema_dir = os.path.expanduser(os.path.join('~', 'etc', 'laurelin', 'server', 'schema.d'))


_kind_factories = {
    'syntax_rules': ('syntax', 'SyntaxRule'),
    'matching_rules': ('matching_rule', 'MatchingRule'),
    'attribute_types': ('attribute_type', 'AttributeType'),
    'object_classes': ('object_class', 'ObjectClass'),
}

_dynamic_classes = {
    'SyntaxRule': 'syntax',
    'AttributeType': 'attribute_type',
    'ObjectClass': 'object_class',
    'ExtensibleObjectClass': 'object_class',
}


def kind_factory(kind):
    modname, classname = _kind_factories[kind]
    mod = import_module('.' + modname, __spec__.parent)
    return getattr(mod, classname)


def dynamic_class(classname):
    modname = _dynamic_classes[classname]
    mod = import_module('.' + modname, __spec__.parent)
    return getattr(mod, classname)


def schema_element(kind, params):
    return kind_factory(kind)(params)


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
        self._schema['syntax_rules']['oid'] = dynamic_class('SyntaxRule')({
            'oid': '1.3.6.1.4.1.1466.115.121.1.38',
            'desc': 'OID',
            'name': 'oid',
            'regex': re_anchor(rfc4512.oid),
        })
        self._schema['attribute_type']['objectClass'] = dynamic_class('AttributeType')({
            'equality_rule': 'objectIdentifierMatch',
            'name': 'objectClass',
            'desc': 'object class',
            'oid': '2.5.4.0',
            'syntax': '1.3.6.1.4.1.1466.115.121.1.38'
        })
        self._schema['object_classes']['top'] = dynamic_class('ObjectClass')({
            'name': 'top',
            'desc': 'top',
            'oid': '2.5.6.0',
            'required_attributes': ['objectClass'],
            'type': 'abstract'
        })
        self._schema['object_classes']['extensibleObject'] = dynamic_class('ExtensibleObjectClass')()

    def load(self):
        self.load_builtin()
        self.load_dir(_schema_dir)

    def load_builtin(self):
        for fn in 'syntax', 'matching_rules', 'schema':
            with resource_stream(__name__, fn + '.yaml') as f:
                self.load_stream(f)

    def load_dir(self, schema_dir):
        files = glob(os.path.join(schema_dir, '*.yaml'))
        files += glob(os.path.join(schema_dir, '*.yml'))
        if not files:
            warn(f'No schema files found in {schema_dir}', LDAPWarning)

        files.sort()
        for fn in files:
            self.load_file(fn)

    def load_file(self, fn):
        with open(fn) as f:
            self.load_stream(f)

    def load_stream(self, f):
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
