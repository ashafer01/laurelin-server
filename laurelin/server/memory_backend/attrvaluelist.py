import re
import warnings

from ..exceptions import *
from ..schema import get_schema

with warnings.catch_warnings():
    warnings.simplefilter('ignore')
    from fuzzywuzzy import fuzz

# TODO make approxMatch min score configurable
APPROX_MATCH_FUZZ_MIN_RATIO = 75


class AttrValueList(list):
    def __init__(self, attr: str):
        list.__init__(self)
        self._schema = get_schema()
        self._attr_type = attr
        self._attr = self._schema.get_attribute_type(attr)

    def _get_rule(self, key):
        try:
            rule = self._attr[key]
        except KeyError:
            raise LDAPError(f'Attribute {self._attr_type} does not have a defined {key}')
        try:
            return self._schema.get_matching_rule(rule)
        except UndefinedSchemaElementError:
            raise LDAPError(f'Attribute {self._attr_type} {key} is not defined')

    def index(self, assertion_value, *args, **kwds):
        try:
            equal = self._get_rule('equality_rule')
            for i, value in enumerate(self):
                if equal(value, assertion_value):
                    return i
        except ValueError:
            raise LDAPError('ValueError occurred while looking for matching value')
        raise ValueError(f'Attribute value "{assertion_value}" does not exist')

    def remove(self, item):
        i = self.index(item)
        self.pop(i)

    def equals(self, assertion_value):
        try:
            self.index(assertion_value)
            return True
        except ValueError:
            return False

    def __contains__(self, item):
        return self.equals(item)

    def __eq__(self, other):
        return self.equals(other)

    def __ne__(self, other):
        return not self.equals(other)

    def less_than(self, assertion_value):
        ordering = self._get_rule('ordering_rule')
        for value in self:
            if ordering(value, assertion_value):
                return True
        return False

    def __lt__(self, other):
        return self.less_than(other)

    def __le__(self, other):
        return self.less_than(other) or self.equals(other)

    def __gt__(self, other):
        return not self.less_than(other) and not self.equals(other)

    def __ge__(self, other):
        return not self.less_than(other)

    def match_substrings(self, substrings):
        """
        Match a Substrings protocol object to any value

        :param laurelin.ldap.rfc4511.Substrings substrings: protocol object representing the substring assertion
        :rtype: bool
        """
        substr_rule = self._get_rule('substrings_rule')
        n = len(substrings)
        sub_name = ''
        sub_strs = []
        first_type = substrings.getComponentByPosition(0).getName()
        if first_type != 'initial':
            sub_strs.append('')
        for i in range(n):
            sub_obj = substrings.getComponentByPosition(i)
            sub_name = sub_obj.getName()
            sub_str = str(sub_obj.getComponent())
            sub_strs.append(re.escape(substr_rule.prepare(sub_str)))
        if sub_name != 'final' and sub_strs[-1] != '':
            sub_strs.append('')
        pattern = '^' + '.*?'.join(sub_strs) + '$'
        for val in self:
            val = substr_rule.prepare(val)
            if re.match(pattern, val):
                return True
        return False

    def match_approx(self, assertion_value):
        equal = self._get_rule('equality_rule')
        assertion_value = equal.prepare(assertion_value)
        for val in self:
            val = equal.prepare(val)
            if fuzz.ratio(val, assertion_value) >= APPROX_MATCH_FUZZ_MIN_RATIO:
                return True
        return False
