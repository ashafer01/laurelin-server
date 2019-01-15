"""
In-memory ephemeral LDAP backend store
"""
import re
from laurelin.ldap.constants import Scope
from laurelin.ldap.protoutils import get_string_component
from laurelin.ldap.utils import CaseIgnoreDict

from .exceptions import LDAPError


class LDAPObject(object):
    def __init__(self, rdn, attrs=None):
        if isinstance(attrs, CaseIgnoreDict):
            pass
        elif attrs is None or isinstance(attrs, dict):
            attrs = CaseIgnoreDict(attrs)
        else:
            raise TypeError('attrs')

        if rdn != '':
            try:
                rdn_attr, rdn_val = rdn.split('=', 1)
            except ValueError:
                raise ValueError('Invalid RDN')

            if rdn_attr not in attrs:
                attrs[rdn_attr] = [rdn_val]
            elif rdn_val not in attrs[rdn_attr]:
                attrs[rdn_attr].append(rdn_val)

        self.rdn = rdn

        self.attrs = attrs
        self.children = {}

    def matches_filter(self, fil):
        if fil is None:
            return True
        filter_type = fil.getName()
        if filter_type == 'and':
            and_obj = fil.getComponent()
            for i in range(len(and_obj)):
                if not self.matches_filter(and_obj.getComponentByPosition(i)):
                    return False
            return True
        elif filter_type == 'or':
            or_obj = fil.getComponent()
            for i in range(len(or_obj)):
                if self.matches_filter(or_obj.getComponentByPosition(i)):
                    return True
            return False
        elif filter_type == 'not':
            not_obj = fil.getComponent()
            not_filter = not_obj.getComponentByName('innerNotFilter')
            return not self.matches_filter(not_filter)
        elif filter_type == 'equalityMatch':
            ava = fil.getComponent()
            attr = str(ava.getComponentByName('attributeDesc'))
            value = str(ava.getComponentByName('assertionValue'))
            return attr in self.attrs and value in self.attrs[attr]
        elif filter_type == 'substrings':
            subs_obj = fil.getComponent()
            attr_type = str(subs_obj.getComponentByName('type'))
            if attr_type not in self.attrs:
                return False
            subs = subs_obj.getComponentByName('substrings')
            n = len(subs)
            sub_name = ''
            sub_strs = []
            first_type = subs.getComponentByPosition(0).getName()
            if first_type != 'initial':
                sub_strs.append('')
            for i in range(n):
                sub_obj = subs.getComponentByPosition(i)
                sub_name = sub_obj.getName()
                sub_str = str(sub_obj.getComponent())
                sub_strs.append(sub_str)
            if sub_name != 'final' and sub_strs[-1] != '':
                sub_strs.append('')
            pattern = '^' + '.*?'.join(sub_strs) + '$'
            for val in self.attrs[attr_type]:
                if re.match(pattern, val, flags=re.IGNORECASE):
                    return True
            return False
        elif filter_type == 'greaterOrEqual':
            raise LDAPError('Greater or equal filters not yet implemented')
            #ava = fil.getComponent()
            #ret = '({0}>={1})'.format(str(ava.getComponentByName('attributeDesc')),
            #                          str(ava.getComponentByName('assertionValue')))
        elif filter_type == 'lessOrEqual':
            raise LDAPError('Less or equal filters not yet implemented')
            #ava = fil.getComponent()
            #ret = '({0}<={1})'.format(str(ava.getComponentByName('attributeDesc')),
            #                          str(ava.getComponentByName('assertionValue')))
        elif filter_type == 'present':
            present_obj = fil.getComponent()
            attr_type = str(present_obj)
            return attr_type in self.attrs
        elif filter_type == 'approxMatch':
            raise LDAPError('Approx match filters not yet implemented')
            #ava = fil.getComponent()
            #ret = '({0}~={1})'.format(str(ava.getComponentByName('attributeDesc')),
            #                          str(ava.getComponentByName('assertionValue')))
        elif filter_type == 'extensibleMatch':
            raise LDAPError('Extensible match filters not yet implemented')
            #xm_obj = fil.getComponent()

            #rule = ''
            #rule_obj = xm_obj.getComponentByName('matchingRule')
            #if rule_obj.isValue:
            #    rule = ':' + str(rule_obj)

            #attr = ''
            #attr_obj = xm_obj.getComponentByName('type')
            #if attr_obj.isValue:
            #    attr = str(attr_obj)

            #dn_attrs = ':dn' if bool(xm_obj.getComponentByName('dnAttributes')) else ''

            #value = str(xm_obj.getComponentByName('matchValue'))

            #ret = '({0}{1}{2}:={3})'.format(attr, dn_attrs, rule, value)
        else:
            raise LDAPError(f'Non-standard filter type "{filter_type}" in search request is unhandled')

    def add_child(self, rdn, attrs=None):
        self.children[rdn] = LDAPObject(rdn, attrs)

    def get(self, dn):
        suffix = ','+self.rdn
        if dn == self.rdn:
            return self
        elif dn.endswith(suffix):
            dn = dn[0:-len(suffix)]
            next_rdn = dn.split(',')[-1]
            if next_rdn in self.children:
                return self.children[next_rdn].get(dn)
            else:
                raise LDAPError('No such object')
        else:
            raise LDAPError('No such object')

    def base_object(self, filter=None):
        if self.matches_filter(filter):
            return self

    async def filter_children(self, filter=None):
        yield self.base_object(filter)
        for obj in self.children.values():
            if obj.matches_filter(filter):
                yield obj

    async def subtree(self, filter=None):
        yield self.base_object(filter)
        for child in self.children.values():
            async for obj in child.subtree():
                if obj.matches_filter(filter):
                    yield obj


class MemoryBackend(object):
    def __init__(self, base_dn):
        self.suffix = base_dn
        self._dit = LDAPObject(base_dn)
        self._root_dse = LDAPObject('', {
            'namingContexts': [base_dn],
            'defaultNamingContext': [base_dn],
            'supportedLDAPVersion': ['3'],
            'vendorName': ['laurelin'],
        })

    async def search(self, search_request):
        base_dn = get_string_component(search_request, 'baseObject')
        scope = search_request.getComponentByName('scope')
        filter = search_request.getComponentByName('filter') or None

        _limit = search_request.getComponentByName('sizeLimit')
        if _limit.isValue:
            limit = int(_limit)
            if limit == 0:
                return
        else:
            limit = None

        # TODO implement all search parameters
        #search_request.getComponentByName('derefAliases')
        #search_request.getComponentByName('timeLimit')
        #search_request.getComponentByName('typesOnly')

        if base_dn == '':
            result_gen = [self._root_dse]
        else:
            base_obj = self._dit.get(base_dn)
            if scope == Scope.BASE:
                yield base_obj.base_object(filter)
                return
            elif scope == Scope.ONE:
                result_gen = base_obj.filter_children(filter)
            elif scope == Scope.SUB:
                result_gen = base_obj.subtree(filter)
            else:
                raise ValueError('scope')

        n = 0
        async for item in result_gen:
            yield item
            n += 1
            if limit and n >= limit:
                break

    def compare(self, compare_request):
        dn = str(compare_request.getComponentByName('entry'))
        ava = compare_request.getComponentByName('ava')
        attr_type = str(ava.getComponentByName('attributeDesc'))
        attr_value = str(ava.getComponentByName('assertionValue'))

        obj = self._dit.get(dn)
        return attr_type in obj.attrs and attr_value in obj.attrs[attr_type]

    def add(self, add_request):
        dn = str(add_request.getComponentByName('entry'))
        al = add_request.getComponentByName('attributes')
        attrs = {}
        for i in range(len(al)):
            attr = al.getComponentByPosition(i)
            attr_type = str(attr.getComponentByName('type'))
            attr_vals = []
            vals = attr.getComponentByName('vals')
            for j in range(len(vals)):
                attr_vals.append(str(vals.getComponentByPosition(j)))
            attrs[attr_type] = attr_vals

        rdn, parent_dn = dn.split(',', 1)
        parent_obj = self._dit.get(parent_dn)
        parent_obj.add_child(rdn, attrs)

    def delete(self, delete_request):
        # TODO
        pass

    def modify(self, modify_request):
        # TODO
        pass

    def mod_dn(self, mod_dn_request):
        # TODO
        pass
