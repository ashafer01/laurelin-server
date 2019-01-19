import os.path
import re
import string

from collections import defaultdict
from glob import glob

import yaml

from parsimonious.grammar import Grammar
from parsimonious.exceptions import ParseError

from laurelin.ldap import rfc4512, rfc4514, rfc4517
from laurelin.ldap.utils import CaseIgnoreDict, re_anchor, escaped_regex

from .exceptions import *

# TODO make this an env var / CLI startup parameter
_schema_dir = os.path.expanduser('~/etc/laurelin/server/schema.d')


class BaseSchemaElement(object):
    def __init__(self, params):
        self._params = params

    def __getitem__(self, item):
        return self._params[item]

    def __contains__(self, item):
        return item in self._params


class AttributeType(BaseSchemaElement):
    _inherit_keys = ('syntax', 'equality_rule', 'substrings_rule', 'ordering_rule')

    def __init__(self, params):
        if 'syntax' not in params and 'inherits' not in params:
            raise InvalidSchemaError('Attribute type definitions require one of "syntax" or "inherits"')
        params.setdefault('obsolete', False)
        params.setdefault('single_value', False)
        params.setdefault('collective', False)
        params.setdefault('no_user_modification', False)
        params.setdefault('usage', 'userApplications')
        BaseSchemaElement.__init__(self, params)
        self.resolved = False

    def resolve(self):
        if not self.resolved and 'inherits' in self:
            supertype = schema.get_attribute_type(self['inherits'])
            supertype.resolve()
            for key in self._inherit_keys:
                if key not in self:
                    self._params[key] = supertype[key]
        self.resolved = True

    def validate(self, values):
        if self['single_value'] and len(values) > 1:
            raise SchemaValidationError(f'{self["name"]} is single-value')
        syntax = schema.get_syntax_rule(self['syntax'])
        for value in values:
            try:
                syntax.validate(value)
            except SchemaValidationError:
                raise SchemaValidationError(f'Not a valid attribute value for {self["desc"]}')


class ObjectClass(BaseSchemaElement):
    def __init__(self, params):
        params.setdefault('obsolete', False)
        params.setdefault('type', 'structural')
        BaseSchemaElement.__init__(self, params)
        self.required_attrs = {attr.lower() for attr in self['required_attributes']}
        self.allowed_attrs = {attr.lower() for attr in self['allowed_attributes']}
        self.resolved = False

    def merge(self, object_class):
        """Combine another ObjectClass with this one, returning a new ObjectClass"""
        new_oc = ObjectClass(self._params)
        other_oc = schema.get_object_class(object_class)
        new_oc.required_attrs |= other_oc.required_attrs
        new_oc.allowed_attrs |= other_oc.allowed_attrs
        return new_oc

    def resolve(self):
        if not self.resolved and 'inherits' in self:
            try:
                superclass = schema.get_object_class(self['inherits'])
            except KeyError:
                raise InvalidSchemaError(f'superclass {self["inherits"]} for {self["name"]} does not exist')
            superclass.resolve()
            self.required_attrs |= superclass.required_attrs
            self.allowed_attrs |= superclass.allowed_attrs
        self.resolved = True

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

        self.attr_type_validate(attrs)

    def attr_type_validate(self, attrs: dict):
        for attr, values in attrs.items():
            attr_type = schema.get_attribute_type(attr)
            try:
                attr_type.validate(values)
            except SchemaValidationError:
                raise SchemaValidationError(f'Not a valid object class {self["name"]}')


class ExtensibleObjectClass(ObjectClass):
    def __init__(self):
        BaseSchemaElement.__init__(self, {
            'oid': '1.3.6.1.4.1.1466.101.120.111',
            'name': 'extensibleObject',
            'inherits': 'top',
            'type': 'auxiliary',
        })

    def validate(self, attrs: dict):
        for attr in attrs.keys():
            if attr['usage'] != 'userApplications':
                raise SchemaValidationError('Non-user attribute on extensibleObject')

        self.attr_type_validate(attrs)


class FormatFunction(object):
    """Allows things like {escape[\\*]} to be enabled in syntax regexes"""

    def __init__(self, f):
        self.func = f

    def __getitem__(self, item):
        return self.func(item)


_regex_repetition = re.compile(r'^[0-9,]+$')


class SyntaxRegexFormatter(string.Formatter):
    def __init__(self):
        self._extra_kwargs = {
            'rfc4512': rfc4512,
            'rfc4514': rfc4514,
            'rfc4517': rfc4517,
            'escape': FormatFunction(escaped_regex)
        }

    def add_subpattern(self, name, pattern):
        self._extra_kwargs[name] = pattern

    def parse(self, format_string):
        for tpl in string.Formatter.parse(self, format_string):
            literal_text, field_name, _, _ = tpl
            if field_name:
                if _regex_repetition.match(field_name):
                    literal_text += '{' + field_name + '}'
                    yield literal_text, None, None, None
                else:
                    yield tpl
            else:
                yield tpl

    def vformat(self, format_string, args, kwargs):
        kwargs.update(self._extra_kwargs)
        return string.Formatter.vformat(self, format_string, args, kwargs)


class BaseSyntaxRule(BaseSchemaElement):
    def validate(self, value):
        try:
            self.parse(value)
        except SyntaxParseError:
            raise SchemaValidationError(f'"{value}" is not valid syntax {self["desc"]}')

    def parse(self, value):
        raise NotImplemented()


class RegexSyntaxRule(BaseSyntaxRule):
    def __init__(self, params: dict):
        BaseSyntaxRule.__init__(self, params)
        self.formatter = SyntaxRegexFormatter()
        if 'subpatterns' in params:
            for name, pattern in params['subpatterns'].items():
                formatted_pattern = self.formatter.format(pattern)
                self.formatter.add_subpattern(name, formatted_pattern)
        self._re = re.compile(self.formatter.format(params['regex']))

    def parse(self, value):
        m = self._re.match(value)
        if not m:
            raise SyntaxParseError()
        return m


class PEGSyntaxRule(BaseSyntaxRule):
    def __init__(self, params: dict):
        BaseSyntaxRule.__init__(self, params)
        self._grammar = Grammar(params['peg'])

    def parse(self, value):
        try:
            return self._grammar.parse(value)
        except ParseError:
            raise SyntaxParseError()


def SyntaxRule(params: dict):
    if 'regex' in params:
        return RegexSyntaxRule(params)
    elif 'peg' in params:
        return PEGSyntaxRule(params)
    else:
        raise LDAPError('Syntax implementation unknown / not yet implemented')


# TODO make matching rules match things
class MatchingRule(BaseSchemaElement):
    pass


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
