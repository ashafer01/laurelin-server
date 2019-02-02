from .base import get_schema
from .element import BaseSchemaElement
from ..exceptions import *


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
        self.schema = get_schema()

    def resolve(self):
        if not self.resolved and 'inherits' in self:
            supertype = self.schema.get_attribute_type(self['inherits'])
            supertype.resolve()
            for key in self._inherit_keys:
                if key not in self:
                    self._params[key] = supertype[key]
        self.resolved = True

    def validate(self, values):
        if self['single_value'] and len(values) > 1:
            raise SchemaValidationError(f'{self["name"]} is single-value')
        syntax = self.schema.get_syntax_rule(self['syntax'])
        for value in values:
            try:
                syntax.validate(value)
            except SchemaValidationError:
                raise SchemaValidationError(f'Not a valid attribute value for {self["desc"]}')
