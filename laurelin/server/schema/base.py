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
    'syntax_rules': ('.syntax', 'SyntaxRule'),
    'matching_rules': ('.matching_rule', 'MatchingRule'),
    'attribute_types': ('.attribute_type', 'AttributeType'),
    'object_classes': ('.object_class', 'ObjectClass'),
}


def schema_element(kind, params):
    modname, classname = _kind_factories[kind]
    mod = import_module(modname, __package__)
    return getattr(mod, classname)(params)


def _element_getter(kind):
    def get_element(self, ident):
        if ident[0].isdigit():
            dct = self._oids
        else:
            dct = self._schema[kind]
        return dct[ident]
    return get_element


class Schema(object):
    def __init__(self):
        self._schema = defaultdict(CaseIgnoreDict)
        self._oids = {}

        # These shall be the only 4 hard coded schema elements to enable special-casing extensibleObject

        self.load_element('syntax_rules', 'oid', {
            'oid': '1.3.6.1.4.1.1466.115.121.1.38',
            'regex': re_anchor(rfc4512.oid),
        })
        self.load_element('attribute_types', 'objectClass', {
            'desc': 'object class',
            'oid': '2.5.4.0',
            'syntax': '1.3.6.1.4.1.1466.115.121.1.38',
            'equality_rule': 'objectIdentifierMatch',
        })
        self.load_element('object_classes', 'top', {
            'oid': '2.5.6.0',
            'required_attributes': ['objectClass'],
            'type': 'abstract',
        })

        from .object_class import ExtensibleObjectClass
        ext_oc = ExtensibleObjectClass()
        self._schema['object_classes']['extensibleObject'] = ext_oc
        self._oids[ext_oc.OID] = ext_oc

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
                self.load_element(kind, name, params)

    def load_element(self, kind, name, params):
        name = params.setdefault('name', name)
        params.setdefault('desc', name)
        element = schema_element(kind, params)
        self._schema[kind][name] = element
        try:
            self._oids[params['oid']] = element
        except KeyError:
            pass

    def resolve(self):
        """Resolve all inheritance"""
        try:
            for kind in 'object_classes', 'attribute_types':
                for obj in self._schema[kind].values():
                    obj.resolve()
        except KeyError:
            raise InvalidSchemaError('missing inherited schema element')

    get_attribute_type = _element_getter('attribute_types')
    get_object_class = _element_getter('object_classes')
    get_matching_rule = _element_getter('matching_rules')
    get_syntax_rule = _element_getter('syntax_rules')


_schema = None


def get_schema():
    global _schema
    if not _schema:
        _schema = Schema()
    return _schema
