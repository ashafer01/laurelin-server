#!/usr/bin/env python3
"""Import standard or near-standard LDAP schema representations to YAML"""
import os
import os.path
import re
import shlex
import sys

from collections import defaultdict, deque
from warnings import warn

from laurelin.ldap import rfc4512
from laurelin.ldap.utils import find_closing_paren, re_anchor

import yaml


def prepare_input_schema(schema):
    schema = re.sub('(\n|\r|\r\n) *', ' ', schema)
    schema = schema.strip()
    return schema


def split_schema_elements(schema):
    """divide up into elements by finding top-level matching parens"""
    elements = []

    i = 0
    while i < len(schema):
        c = schema[i]
        if c == '(':
            end = find_closing_paren(schema[i:])
            element = schema[i+1:i+end].strip()
            elements.append(element)
            i += end+1
        else:
            i += 1

    return elements


class SchemaImportScriptError(Exception):
    pass


_oid_re = re.compile(re_anchor(rfc4512.numericoid))


def _get_oids_list(tokens_deque):
    oids = []
    in_parens = False
    while True:
        try:
            token = tokens_deque.popleft()
        except IndexError:
            if in_parens:
                raise SchemaImportScriptError('missing closing paren')
            break
        if token == '(':
            in_parens = True
        elif token == '$':
            if not in_parens:
                raise SchemaImportScriptError('Invalid oid: $')
            pass
        elif token == ')':
            if not in_parens:
                raise SchemaImportScriptError('missing opening paren')
            break
        elif (token == 'MUST' or token == 'MAY' or token == 'ABSTRACT' or token == 'STRUCTURAL' or token == 'AUXILIARY'
                or token.startswith('X-')):
            raise SchemaImportScriptError('invalid object class - ran off end of oid list')
        else:
            oids.append(token)
            if not in_parens:
                break
    return oids


def format_object_class(element):
    tokens = deque(shlex.split(element))

    name = None
    params = {}

    oid = tokens.popleft()
    if not _oid_re.match(oid):
        raise SchemaImportScriptError(f'object class spec has invalid OID: {oid}')
    params['oid'] = oid

    while True:
        try:
            token = tokens.popleft()
        except IndexError:
            break
        if token == 'NAME':
            name = tokens.popleft()
        elif token == 'DESC':
            params['description'] = tokens.popleft()
        elif token == 'OBSOLETE':
            params['obsolete'] = True
        elif token == 'SUP':
            params['inherits'] = tokens.popleft()
        elif token == 'ABSTRACT':
            if 'type' in params:
                raise SchemaImportScriptError('object class has multiple kind/type keywords')
            params['type'] = 'abstract'
        elif token == 'STRUCTURAL':
            if 'type' in params:
                raise SchemaImportScriptError('object class has multiple kind/type keywords')
            params['type'] = 'structural'
        elif token == 'AUXILIARY':
            if 'type' in params:
                raise SchemaImportScriptError('object class has multiple kind/type keywords')
            params['type'] = 'auxiliary'
        elif token == 'MUST':
            params['required_attributes'] = _get_oids_list(tokens)
        elif token == 'MAY':
            params['allowed_attributes'] = _get_oids_list(tokens)
        elif token.startswith('X-'):
            warn('Object class extensions are unhandled and ignored')
        else:
            warn(f'Unhandled and ignored token in object class: {token}')

    if not name:
        raise SchemaImportScriptError('object class missing NAME')

    return name, params


def format_attribute_type(element):
    tokens = deque(shlex.split(element))

    name = None
    params = {}

    oid = tokens.popleft()
    if not _oid_re.match(oid):
        raise SchemaImportScriptError(f'object class spec has invalid OID: {oid}')
    params['oid'] = oid

    while True:
        try:
            token = tokens.popleft()
        except IndexError:
            break
        if token == 'NAME':
            name = tokens.popleft()
        elif token == 'DESC':
            params['description'] = tokens.popleft()
        elif token == 'OBSOLETE':
            params['obsolete'] = True
        elif token == 'SUP':
            params['inherits'] = tokens.popleft()
        elif token == 'EQUALITY':
            params['equality_rule'] = tokens.popleft()
        elif token == 'ORDERING':
            params['ordering_rule'] = tokens.popleft()
        elif token == 'SUBSTR':
            params['substrings_rule'] = tokens.popleft()
        elif token == 'SYNTAX':
            params['syntax'] = tokens.popleft()
        elif token == 'SINGLE-VALUE':
            params['single_value'] = True
        elif token == 'COLLECTIVE':
            params['collective'] = True
        elif token == 'NO-USER-MODIFICATION':
            params['no_user_modification'] = True
        elif token == 'USAGE':
            params['usage'] = tokens.popleft()
        elif token.startswith('X-'):
            warn('Attribute type extensions are unhandled and ignored')
        else:
            warn(f'Unhandled and ignored token in attribute type: {token}')

    if not name:
        raise SchemaImportScriptError('attribute type missing NAME')

    return name, params


_oc_keywords = ('STRUCTURAL', 'ABSTRACT', 'AUXILIARY', 'MUST', 'MAY')


def format_elements(elements):
    element_groups = defaultdict(dict)
    for e in elements:
        is_oc = False
        for word in _oc_keywords:
            if word in e:
                is_oc = True
                name, params = format_object_class(e)
                element_groups['object_classes'][name] = params
                break
        if not is_oc:
            name, params = format_attribute_type(e)
            element_groups['attribute_types'][name] = params
    return dict(element_groups)


def main():
    opened = False
    try:
        if len(sys.argv) < 2 or sys.argv[1] == '-':
            source = sys.stdin
        else:
            source = open(os.path.expanduser(sys.argv[1]))
            opened = True

        schema = prepare_input_schema(source.read())
        elements = split_schema_elements(schema)
        formatted = format_elements(elements)
        print(yaml.dump(formatted, default_flow_style=False))
    finally:
        if opened:
            source.close()


if __name__ == '__main__':
    main()
