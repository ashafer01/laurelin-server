import re
import string

from parsimonious.grammar import Grammar
from parsimonious.exceptions import ParseError

from laurelin.ldap import rfc4512, rfc4514, rfc4517
from laurelin.ldap.utils import escaped_regex

from .element import BaseSchemaElement
from ..exceptions import *


class FormatFunction(object):
    """Allows things like {escape[\\*]} to be enabled in syntax regexes"""

    def __init__(self, f):
        self.func = f

    def __getitem__(self, item):
        return self.func(item)


_regex_repetition = re.compile(r'^[0-9]+(,[0-9]+)?$')


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
        try:
            self._re = re.compile(self.formatter.format(params['regex']))
        except Exception:
            raise InvalidSchemaError(f'Failed to compile regex syntax for {params["name"]}')

    def parse(self, value):
        m = self._re.match(value)
        if not m:
            raise SyntaxParseError()
        return m


class PEGSyntaxRule(BaseSyntaxRule):
    def __init__(self, params: dict):
        BaseSyntaxRule.__init__(self, params)
        try:
            self._grammar = Grammar(params['peg'])
        except Exception:
            raise InvalidSchemaError(f'Failed to parse PEG grammar for {params["name"]}')

    def parse(self, value):
        try:
            return self._grammar.parse(value)
        except ParseError:
            raise SyntaxParseError()


class OctetStringSyntax(BaseSyntaxRule):
    def parse(self, value):
        return value


def normalize_phone_number(value):
    # strip out non-digit and non-plus characters
    s = re.sub('[^0-9+]', '', value)

    # remove leading +
    has_plus = False
    if s.startswith('+'):
        has_plus = True
        s = s[1:]

    # Should only have numbers now
    if not s.isdigit():
        return SchemaValidationError()

    # Check length
    l = len(s)
    if l < 7 or l > 15:
        return SchemaValidationError()

    if has_plus:
        s = '+' + s

    return s


class ParsedFaxNumber(object):
    def __init__(self, norm_number, params):
        self.number = norm_number
        self.params = params


class FacsimileTelephoneNumberSyntax(BaseSyntaxRule):
    _fax_parameters = (
        'twodimensional',
        'fineresolution',
        'unlimitedlength',
        'b4length',
        'a3width',
        'b4width',
        'uncompressed',
    )

    def parse(self, value):
        params = value.split('$')
        try:
            norm_number = normalize_phone_number(params[0])
        except SchemaValidationError:
            raise SchemaValidationError(f'Invalid phone number for {self["name"]}')
        for param in params[1:]:
            if param.lower() not in self._fax_parameters:
                raise SchemaValidationError(f'Not a valid {self["name"]} - invalid fax parameter')
        return ParsedFaxNumber(norm_number, params[1:])


class TelephoneNumberSyntax(BaseSyntaxRule):
    def parse(self, value):
        return normalize_phone_number(value)


custom_syntax_implementations = {
    '1.3.6.1.4.1.1466.115.121.1.22': FacsimileTelephoneNumberSyntax,
    '1.3.6.1.4.1.1466.115.121.1.50': TelephoneNumberSyntax,
}


def SyntaxRule(params: dict):
    if 'regex' in params:
        return RegexSyntaxRule(params)
    elif 'peg' in params:
        return PEGSyntaxRule(params)
    elif 'octet_string' in params and params['octet_string']:
        return OctetStringSyntax(params)
    elif 'custom' in params and params['custom']:
        if 'oid' not in params:
            raise InvalidSchemaError('oid is required for custom syntax implementations')
        return custom_syntax_implementations[params['oid']](params)
    else:
        raise LDAPError('Syntax implementation unknown / not yet implemented')
