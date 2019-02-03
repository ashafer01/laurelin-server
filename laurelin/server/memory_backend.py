"""
In-memory ephemeral LDAP backend store
"""
import re

from laurelin.ldap.constants import Scope
from laurelin.ldap.modify import Mod
from laurelin.ldap.protoutils import split_unescaped, seq_to_list

from .attrsdict import AttrsDict
from .dn import parse_rdn, parse_dn
from .exceptions import LDAPError
from .schema.object_class import ObjectClass


class LDAPObject(object):
    def __init__(self, rdn: str, attrs=None):
        if isinstance(attrs, AttrsDict):
            pass
        elif attrs is None or isinstance(attrs, dict):
            attrs = AttrsDict(attrs)
        else:
            raise TypeError('attrs')

        self.rdn = parse_rdn(rdn)

        for rdn_attr, rdn_val in self.rdn:
            if rdn_attr not in attrs:
                attrs[rdn_attr] = [rdn_val]
            elif rdn_val not in attrs[rdn_attr]:
                attrs[rdn_attr].append(rdn_val)

        try:
            oc_attr = attrs['objectClass']
            self.object_class = ObjectClass({'name': 'virtualMergedObjectClass', 'desc': 'Combined object classes'})
            for oc_name in oc_attr:
                self.object_class.merge(oc_name)
        except KeyError:
            self.object_class = None

        self.attrs = attrs
        self.children = {}

    def limited_attrs_copy(self, attrs=None):
        new_attrs = self.attrs.deepcopy(attrs)
        copy = LDAPObject(self.rdn, new_attrs)
        copy.children = self.children.copy()
        return copy

    def validate(self):
        if self.object_class:
            self.object_class.validate(self.attrs)

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
            # TODO greaterOrEqual filter - needs matching rules
            raise LDAPError('Greater or equal filters not yet implemented')
            #ava = fil.getComponent()
            #ret = '({0}>={1})'.format(str(ava.getComponentByName('attributeDesc')),
            #                          str(ava.getComponentByName('assertionValue')))
        elif filter_type == 'lessOrEqual':
            # TODO lessOrEqual filter - needs matching rules
            raise LDAPError('Less or equal filters not yet implemented')
            #ava = fil.getComponent()
            #ret = '({0}<={1})'.format(str(ava.getComponentByName('attributeDesc')),
            #                          str(ava.getComponentByName('assertionValue')))
        elif filter_type == 'present':
            present_obj = fil.getComponent()
            attr_type = str(present_obj)
            return attr_type in self.attrs
        elif filter_type == 'approxMatch':
            # TODO approxMatch filter
            raise LDAPError('Approx match filters not yet implemented')
            #ava = fil.getComponent()
            #ret = '({0}~={1})'.format(str(ava.getComponentByName('attributeDesc')),
            #                          str(ava.getComponentByName('assertionValue')))
        elif filter_type == 'extensibleMatch':
            # TODO extensibleMatch filter
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
        obj = LDAPObject(rdn, attrs)
        obj.validate()
        self.add_child_ref(obj)

    def add_child_ref(self, obj):
        if obj.rdn in self.children:
            raise LDAPError('Object already exists')
        self.children[obj.rdn] = obj

    def delete_child(self, rdn):
        if not self.children[rdn].children:
            self.del_child_ref(rdn)
        else:
            raise LDAPError('Object is non-leaf, cannot delete')

    def del_child_ref(self, rdn):
        del self.children[rdn]

    def get_child(self, rdn):
        rdn = parse_rdn(rdn)
        try:
            return self.children[rdn]
        except KeyError:
            raise LDAPError('No such object')

    def get(self, dn):
        dn = parse_dn(dn)
        if len(dn) == 1 and dn[0] == self.rdn:
            return self
        elif dn[-1] == self.rdn:
            dn = dn[0:-1]
            next_obj = self.get_child(dn[-1])
            return next_obj.get(dn)
        else:
            raise LDAPError('No such object')

    def mod_rdn(self, rdn, new_rdn, del_old_rdn_attr):
        if rdn == new_rdn:
            return

        obj = self.get_child(rdn)
        self.del_child_ref(rdn)
        self.children[new_rdn] = obj

        if del_old_rdn_attr:
            rdn_attr, rdn_val = split_unescaped(rdn, '=', 1)
            self.delete_attr_value(rdn_attr, rdn_val)

    def delete_attr_value(self, attr, value):
        try:
            attr = self.attrs[attr]
        except KeyError:
            return
        try:
            attr.remove(value)
        except ValueError:
            pass

    def modify(self, changes):
        for i in range(len(changes)):
            change = changes.getComponentByPosition(i)
            op = change.getComponentByName('operation')
            mod = change.getComponentByName('modification')
            attr_type = str(mod.getComponentByName('type'))
            attr_vals = seq_to_list(mod.getComponentByName('vals'))

            try:
                if op == Mod.ADD:
                    vals = self.attrs.setdefault(attr_type, [])
                    vals.extend(attr_vals)
                elif op == Mod.REPLACE:
                    if not attr_vals:
                        del self.attrs[attr_type]
                    else:
                        self.attrs[attr_type] = attr_vals
                elif op == Mod.DELETE:
                    if not attr_vals:
                        del self.attrs[attr_type]
                    else:
                        for val in attr_vals:
                            try:
                                self.attrs[attr_type].remove(val)
                            except ValueError:
                                pass
                else:
                    raise LDAPError('Invalid modify operation')
            except KeyError:
                raise LDAPError(f'No such attribute {attr_type} on object')

    async def onelevel(self, filter=None):
        if self.matches_filter(filter):
            yield self
        for obj in self.children.values():
            if obj.matches_filter(filter):
                yield obj

    async def subtree(self, filter=None):
        if self.matches_filter(filter):
            yield self
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
        _limit = search_request.getComponentByName('sizeLimit')
        if _limit.isValue:
            limit = int(_limit)
            if limit == 0:
                return
        else:
            limit = None

        base_dn = str(search_request.getComponentByName('baseObject'))
        scope = search_request.getComponentByName('scope')

        if base_dn == '' and scope == Scope.BASE:
            yield self._root_dse
            return

        fil = search_request.getComponentByName('filter') or None

        _attrs = search_request.getComponentByName('attributes')
        if _attrs.isValue:
            attrs = seq_to_list(_attrs)
        else:
            attrs = None

        # TODO implement all search parameters
        #search_request.getComponentByName('derefAliases')
        #search_request.getComponentByName('timeLimit')
        #search_request.getComponentByName('typesOnly')

        base_obj = self._dit.get(base_dn)
        if scope == Scope.BASE:
            if base_obj.matches_filter(fil):
                yield base_obj.limited_attrs_copy(attrs)
            return
        elif scope == Scope.ONE:
            result_gen = base_obj.onelevel(fil)
        elif scope == Scope.SUB:
            result_gen = base_obj.subtree(fil)
        else:
            raise ValueError('scope')

        n = 0
        async for item in result_gen:
            yield item.limited_attrs_copy(attrs)
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

    def modify(self, modify_request):
        dn = str(modify_request.getComponentByName('object'))
        changes = modify_request.getComponentByName('changes')
        obj = self._dit.get(dn)
        obj.modify(changes)

    def _get_rdn_and_parent(self, dn):
        rdn, parent_dn = split_unescaped(dn, ',', 1)
        parent_obj = self._dit.get(parent_dn)
        return rdn, parent_obj

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

        rdn, parent_obj = self._get_rdn_and_parent(dn)
        parent_obj.add_child(rdn, attrs)

    def delete(self, delete_request):
        dn = str(delete_request)
        rdn, parent_obj = self._get_rdn_and_parent(dn)
        parent_obj.delete_child(rdn)

    def mod_dn(self, mod_dn_request):
        dn = str(mod_dn_request.getComponentByName('entry'))
        new_rdn = str(mod_dn_request.getComponentByName('newrdn'))
        del_old_rdn_attr = bool(mod_dn_request.getComponentByName('deleteoldrdn'))
        _new_parent = mod_dn_request.getComponentByName('newSuperior')

        rdn, parent_obj = self._get_rdn_and_parent(dn)
        if _new_parent.isValue:
            new_parent_obj = self._dit.get(str(_new_parent))
            obj = parent_obj.get_child(rdn)
            parent_obj.del_child_ref(rdn)
            new_parent_obj.add_child_ref(obj)
        else:
            parent_obj.mod_rdn(rdn, new_rdn, del_old_rdn_attr)
