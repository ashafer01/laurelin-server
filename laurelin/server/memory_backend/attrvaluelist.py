import re

from ..exceptions import *
from ..schema import get_schema


class AttrValueList(list):
    def __init__(self, attr: str):
        list.__init__(self)
        self._schema = get_schema()
        self._attr_type = attr
        self._attr = self._schema.get_attribute_type(attr)

    def index(self, assertion_value, *args, **kwds):
        try:
            rule = self._attr['equality_rule']
        except KeyError:
            raise LDAPError(f'Attribute {self._attr_type} does not have a defined equality matching rule')
        try:
            equal = self._schema.get_matching_rule(rule)
            for i, value in enumerate(self):
                if equal(value, assertion_value):
                    return i
            raise ValueError(f'Attribute value "{assertion_value}" does not exist')
        except UndefinedSchemaElementError:
            raise LDAPError(f'Attribute {self._attr_type} equality matching rule is not defined')

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
        try:
            rule = self._attr['ordering_rule']
        except KeyError:
            raise LDAPError(f'Attribute {self._attr_type} does not have a defined ordering rule')
        try:
            ordering = self._schema.get_matching_rule(rule)
            for value in self:
                if ordering(value, assertion_value):
                    return True
            return False
        except UndefinedSchemaElementError:
            raise LDAPError(f'Attribute {self._attr_type} ordering rule is not defined')

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
        try:
            rule = self._attr['substrings_rule']
        except KeyError:
            raise LDAPError(f'Attribute {self._attr_type} does not have a defined substrings rule')
        try:
            substr_rule = self._schema.get_matching_rule(rule)
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
        except UndefinedSchemaElementError:
            raise LDAPError(f'Attribute {self._attr_type} substrings rule is not defined')
