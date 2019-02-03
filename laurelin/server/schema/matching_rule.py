from .base import get_schema
from .element import BaseSchemaElement
from ..dn import parse_dn
from ..exceptions import *

from laurelin.ldap import rfc4518

prep_routines = {
    'case_exact': (
        rfc4518.Transcode,
        rfc4518.Map.characters,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.space,
    ),
    'case_ignore': (
        rfc4518.Transcode,
        rfc4518.Map.all,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.space,
    ),
    'parse_dn': (parse_dn,),
    'none': (),
}


class PreparedString(str):
    pass


class MatchingRule(BaseSchemaElement):
    def __init__(self, params: dict):
        BaseSchemaElement.__init__(self, params)
        self.schema = get_schema()
        if isinstance(params['prep'], str):
            # use pre-defined prep routine
            self._prep_routine = prep_routines[params['prep']]
        elif isinstance(params['prep'], list):
            # combine a set of routines
            self._prep_routine = ()
            for routine in params['prep']:
                self._prep_routine += prep_routines[routine]
        else:
            raise ValueError('prep parameter must be string naming pre-defined prep routine or list of names to combine')

    def prepare(self, value):
        for prep_method in self._prep_routine:
            value = prep_method(value)
        return PreparedString(value)

    def __call__(self, attribute_value, assertion_value):
        if 'syntax' in self:
            assertion_syntax = self.schema.get_syntax_rule(self['syntax'])
            assertion_syntax.validate(assertion_value)

        if not isinstance(attribute_value, PreparedString):
            attribute_value = self.prepare(attribute_value)
        if not isinstance(assertion_value, PreparedString):
            assertion_value = self.prepare(assertion_value)

        if self['usage'] == 'equality':
            return attribute_value == assertion_value
        elif self['usage'] == 'ordering':
            return attribute_value < assertion_value
        elif self['usage'] == 'substring':
            # TODO substring matching rules
            raise LDAPError('substring matching rules not yet implemented')
        else:
            raise ValueError('invalid matching rule usage param')
