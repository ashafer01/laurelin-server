from laurelin.ldap import rfc4511, DerefAliases
from laurelin.ldap.filter import parse as parse_filter
from laurelin.ldap.protoutils import seq_to_list

from .utils import optional_component, bool_component, list_component, require_component, str_component, int_component


class DataBackendMeta(type):
    def __new__(mcs, name, bases, dct):
        cls = type.__new__(mcs, name, bases, dct)
        if name == 'DataBackend':
            # This defines a mapping of required attributes based on the definition of DataBackend
            # Attributes where another attribute has its name as a prefix MUST have one or both of those two
            # overridden by subclasses
            # Defining neither is an error and would lead to infinite recursion if not checked for
            mcs.required_def_map = {}
            attrs = list(dct.keys())
            for attr in attrs:
                if attr[0] == '_':
                    continue
                prefix = attr + '_'
                for cmp_attr in attrs:
                    if cmp_attr.startswith(prefix):
                        mcs.required_def_map[attr] = cmp_attr
                        mcs.required_def_map[cmp_attr] = attr
                        break

            # delete is a special case since a DeleteRequest is just a string (the DN to delete)
            mcs.required_def_map['delete'] = 'delete'
        else:
            required_attrs = set(mcs.required_def_map.keys())
            for attr in dct.keys():
                if attr[0] == '_':
                    continue
                try:
                    dont_need = mcs.required_def_map[attr]
                except KeyError:
                    # If this attribute is not in the map based on DataBackend, we don't care about it
                    continue

                # Try both of these separately to allow both to be defined, and checked in either order
                try:
                    required_attrs.remove(attr)
                except KeyError:
                    pass
                try:
                    required_attrs.remove(dont_need)
                except KeyError:
                    pass
            if required_attrs:
                # Subclass didn't define enough things
                already_noted = set()
                need = []
                for attr in required_attrs:
                    if attr in already_noted:
                        continue
                    other = mcs.required_def_map[attr]
                    pair = [attr, other]
                    pair.sort()
                    need.append('({}, {})'.format(*pair))
                    already_noted.add(other)
                need = '; '.join(need)
                raise RuntimeError(f'Data backend class {name} must override at least one of the DataBackend methods '
                                   f'from each of the following pairs: {need}')
        return cls


class DataBackend(object, metaclass=DataBackendMeta):
    def __init__(self, suffix, conf):
        self.suffix = suffix
        self.conf = conf
        self.default = self.conf.get('default', False)

    async def search(self, search_request):
        base_dn = require_component(search_request, 'baseObject', str)
        scope = require_component(search_request, 'scope')
        fil = optional_component(search_request, 'filter')
        attrs = list_component(search_request, 'attributes')
        types_only = bool_component(search_request, 'typesOnly', default=False)
        deref_aliases = optional_component(search_request, 'derefAliases')
        limit = int_component(search_request, 'sizeLimit')
        time_limit = int_component(search_request, 'timeLimit')

        async for res in self.search_params(base_dn, scope, fil, attrs, deref_aliases, types_only, limit, time_limit):
            yield res

    async def search_params(self, base_dn: str, scope: rfc4511.Scope, fil: str = None,
                            attrs: list = None, deref_aliases: rfc4511.DerefAliases = None, types_only: bool = False,
                            limit: int = 0, time_limit: int = 0):
        req = rfc4511.SearchRequest()
        req.setComponentByName('baseObject', rfc4511.LDAPDN(base_dn))
        req.setComponentByName('scope', scope)
        if fil:
            req.setComponentByName('filter', parse_filter(fil))
        if attrs:
            attr_sel = rfc4511.AttributeSelection()
            for i, attr in enumerate(attrs):
                attr_sel.setComponentByPosition(i, attr)
            req.setComponentByName('attributes', attr_sel)
        if deref_aliases is None:
            deref_aliases = DerefAliases.NEVER
        req.setComponentByName('derefAliases', deref_aliases)
        req.setComponentByName('typesOnly', rfc4511.TypesOnly(types_only))
        req.setComponentByName('sizeLimit', rfc4511.Integer0ToMax(limit))
        req.setComponentByName('timeLimit', rfc4511.Integer0ToMax(time_limit))

        async for res in self.search(req):
            yield res

    async def compare(self, compare_request):
        dn = require_component(compare_request, 'entry', str)
        ava = require_component(compare_request, 'ava')
        attr_type = require_component(ava, 'attributeDesc', str)
        attr_value = require_component(ava, 'assertionValue', str)  # TODO binary support

        return await self.compare_params(dn, attr_type, attr_value)

    async def compare_params(self, dn, attr_type, attr_value):
        req = rfc4511.CompareRequest()
        req.setComponentByName('entry', rfc4511.LDAPDN(dn))
        ava = rfc4511.AttributeValueAssertion()
        ava.setComponentByName('attributeDesc', rfc4511.AttributeDescription(attr_type))
        ava.setComponentByName('assertionValue', rfc4511.AssertionValue(attr_value))
        req.setComponentByName('ava', ava)

        return await self.compare(req)

    async def add(self, add_request):
        dn = require_component(add_request, 'entry', str)
        al = require_component(add_request, 'attributes')
        attrs = {}
        for i in range(len(al)):
            attr = require_component(al, i)
            attr_type = require_component(attr, 'type', str)
            attr_vals = []
            vals = require_component(attr, 'vals')
            for j in range(len(vals)):
                attr_vals.append(require_component(vals, j, str))
            attrs[attr_type] = attr_vals

        return await self.add_params(dn, attrs)

    async def add_params(self, dn: str, attrs: dict):
        req = rfc4511.AddRequest()
        req.setComponentByName('entry', rfc4511.LDAPDN(dn))
        al = rfc4511.AttributeList()
        if attrs:
            i = 0
            for attr_type, attr_vals in attrs.items():
                attr = rfc4511.Attribute()
                attr.setComponentByName('type', rfc4511.AttributeDescription(attr_type))
                vals = rfc4511.Vals()
                j = 0
                for val in attr_vals:
                    vals.setComponentByPosition(j, rfc4511.AttributeValue(val))
                    j += 1
                attr.setComponentByName('vals', vals)
                al.setComponentByPosition(i, attr)
                i += 1
        req.setComponentByName('attributes', al)

        return await self.add(req)

    async def modify(self, modify_request):
        dn = require_component(modify_request, 'object', str)
        changes = require_component(modify_request, 'changes')
        mod_list = []
        for i in range(len(changes)):
            change = changes.getComponentByPosition(i)
            op = change.getComponentByName('operation')
            mod = change.getComponentByName('modification')
            attr_type = str(mod.getComponentByName('type'))
            attr_vals = seq_to_list(mod.getComponentByName('vals'))
            mod_list.append((op, attr_type, attr_vals))
        return await self.modify_params(dn, mod_list)

    async def modify_params(self, dn, mod_list):
        req = rfc4511.ModifyRequest()
        req.setComponentByName('object', rfc4511.LDAPDN(dn))
        changes = rfc4511.Changes()
        for i, mod_op in enumerate(mod_list):
            op, attr_type, attr_vals = mod_op
            change = rfc4511.Change()
            change.setComponentByName('operation', op)
            mod = rfc4511.PartialAttribute()
            mod.setComponentByName('type', rfc4511.Type(attr_type))
            vals = rfc4511.Vals()
            for j, val in enumerate(attr_vals):
                vals.setComponentByPosition(j, val)
            mod.setComponentByName('vals', vals)
            change.setComponentByName('modification', mod)
            changes.setComponentByPosition(i, change)
        req.setComponentByName('changes', changes)
        return await self.modify(req)

    async def mod_dn(self, mod_dn_request):
        dn = require_component(mod_dn_request, 'entry', str)
        new_rdn = require_component(mod_dn_request, 'newrdn', str)
        del_old_rdn_attr = require_component(mod_dn_request, 'deleteoldrdn', bool)
        new_parent = str_component(mod_dn_request, 'newSuperior')

        return await self.mod_dn_params(dn, new_rdn, del_old_rdn_attr, new_parent)

    async def mod_dn_params(self, dn, new_rdn, del_old_rdn_attr, new_parent=None):
        req = rfc4511.ModifyDNRequest()
        req.setComponentByName('entry', rfc4511.LDAPDN(dn))
        req.setComponentByName('newrdn', rfc4511.RelativeLDAPDN(new_rdn))
        req.setComponentByName('deleteoldrdn', rfc4511.DeleteOldRDN(del_old_rdn_attr))
        if new_parent:
            req.setComponentByName('newSuperior', rfc4511.NewSuperior(new_parent))

        return await self.mod_dn(req)

    async def delete(self, delete_request):
        raise NotImplementedError()
