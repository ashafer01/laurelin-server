import os.path

from collections import defaultdict
from glob import glob
from importlib import import_module
from pkg_resources import resource_stream

import yaml

from laurelin.ldap import rfc4512
from laurelin.ldap.utils import CaseIgnoreDict, re_anchor

from ..exceptions import *

# TODO make schema filesystem location configurable
_schema_dir = None


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
        try:
            return dct[ident]
        except KeyError:
            raise UndefinedSchemaElementError(f'Schema element {ident} of kind {kind} is not defined')
    return get_element


class Schema(object):
    def __init__(self):
        self._schema = defaultdict(CaseIgnoreDict)
        self._oids = {}

    def load(self):
        self.load_builtin()

        if _schema_dir:
            try:
                self.load_dir(_schema_dir)
            except SchemaLoadError:
                pass

    def load_builtin(self):
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
        self._schema['object_classes'][ext_oc.NAME] = ext_oc
        self._oids[ext_oc.OID] = ext_oc

        for fn in 'syntax', 'matching_rules', 'schema':
            with resource_stream(__name__, fn + '.yaml') as f:
                self.load_stream(f)

    def load_dir(self, schema_dir):
        if not os.path.isdir(schema_dir):
            raise SchemaLoadError(f'Schema directory {schema_dir} does not exist or is not a directory')

        files = glob(os.path.join(schema_dir, '*.yaml'))
        files += glob(os.path.join(schema_dir, '*.yml'))
        if not files:
            raise SchemaLoadError(f'No schema files found in {schema_dir}')

        files.sort()
        for fn in files:
            self.load_file(fn)

    def load_file(self, fn):
        try:
            with open(fn) as f:
                self.load_stream(f)
        except OSError:
            raise SchemaLoadError(f'Error opening file {fn}')

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
        return element

    def resolve(self):
        """Resolve all inheritance"""
        try:
            for kind in 'object_classes', 'attribute_types':
                for obj in self._schema[kind].values():
                    obj.resolve()
        except UndefinedSchemaElementError:
            raise InvalidSchemaError('missing inherited schema element')

    _get_attribute_type = _element_getter('attribute_types')

    def get_attribute_type(self, ident):
        try:
            return self._get_attribute_type(ident)
        except UndefinedSchemaElementError:
            # TODO make allowing undefined attribute types configurable
            if ident[0].isdigit():
                raise UndefinedSchemaElementError(f'Cannot create default attribute type definition for OID {ident}')
            element = self.load_element('attribute_types', ident, {
                'syntax': 'octet_string',
                'equality_rule': 'laurelin_default_equality_rule',
                'desc': f'Default attribute type for {ident}',
            })
            return element

    get_object_class = _element_getter('object_classes')
    get_matching_rule = _element_getter('matching_rules')
    get_syntax_rule = _element_getter('syntax_rules')


_schema = None


def get_schema():
    global _schema
    if not _schema:
        _schema = Schema()
    return _schema
