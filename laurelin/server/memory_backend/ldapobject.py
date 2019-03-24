from laurelin.ldap.modify import Mod
from laurelin.ldap.protoutils import split_unescaped, seq_to_list

from .attrsdict import AttrsDict

from .. import search_results
from ..dn import parse_rdn, parse_dn
from ..exceptions import *
from ..schema.object_class import ObjectClass


class LDAPObject(object):
    def __init__(self, rdn: str, parent_suffix=None, attrs=None):
        if isinstance(attrs, AttrsDict):
            pass
        elif attrs is None or isinstance(attrs, dict):
            attrs = AttrsDict(attrs)
        else:
            raise TypeError('attrs')

        self.rdn = parse_rdn(rdn)
        if parent_suffix:
            self.dn_str = f'{rdn},{parent_suffix}'
        else:
            self.dn_str = str(rdn)

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

    def to_result(self, attrs=None, types_only=False):
        new_attrs = self.attrs.deepcopy(attrs, types_only)
        return search_results.Entry(self.dn_str, new_attrs)

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
            return attr in self.attrs and self.attrs[attr] == value
        elif filter_type == 'substrings':
            subs_obj = fil.getComponent()
            attr = str(subs_obj.getComponentByName('type'))
            subs = subs_obj.getComponentByName('substrings')
            return attr in self.attrs and self.attrs[attr].match_substrings(subs)
        elif filter_type == 'greaterOrEqual':
            ava = fil.getComponent()
            attr = str(ava.getComponentByName('attributeDesc'))
            value = str(ava.getComponentByName('assertionValue'))
            return attr in self.attrs and self.attrs[attr] >= value
        elif filter_type == 'lessOrEqual':
            ava = fil.getComponent()
            attr = str(ava.getComponentByName('attributeDesc'))
            value = str(ava.getComponentByName('assertionValue'))
            return attr in self.attrs and self.attrs[attr] <= value
        elif filter_type == 'present':
            present_obj = fil.getComponent()
            attr = str(present_obj)
            if attr.lower() == 'objectclass':
                return True
            return attr in self.attrs
        elif filter_type == 'approxMatch':
            ava = fil.getComponent()
            attr = str(ava.getComponentByName('attributeDesc'))
            value = str(ava.getComponentByName('assertionValue'))
            return attr in self.attrs and self.attrs[attr].match_approx(value)
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
            raise LDAPError(f'Non-standard filter type "{filter_type}" is unhandled')

    def add_child(self, rdn, attrs=None):
        obj = LDAPObject(rdn, self.dn_str, attrs)
        obj.validate()
        self.add_child_ref(obj)

    def add_child_ref(self, obj):
        if obj.rdn in self.children:
            raise EntryAlreadyExistsError('Object already exists')
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
            raise BaseObjectNotFound('No such object', self.dn_str)

    def mod_rdn(self, rdn, new_rdn, del_old_rdn_attr):
        if rdn == new_rdn:
            return

        obj = self.get_child(rdn)
        self.del_child_ref(rdn)
        self.children[new_rdn] = obj

        if del_old_rdn_attr:
            rdn_attr, rdn_val = split_unescaped(rdn, '=')
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
                    vals = self.attrs.setdefault(attr_type)
                    for val in attr_vals:
                        if val in vals:
                            # the client asked us to add a value equivalent to an existing one
                            continue
                        vals.append(val)
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
                                # the client asked us to delete a value that does not exist
                                pass
                else:
                    raise ProtocolError('Invalid modify operation')
            except KeyError:
                raise NoSuchAttributeError(f'No such attribute {attr_type} on object {self.dn_str}')

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
