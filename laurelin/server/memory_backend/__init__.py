"""
In-memory ephemeral LDAP backend store
"""
from laurelin.ldap.constants import Scope
from laurelin.ldap.protoutils import split_unescaped, seq_to_list

from .ldapobject import LDAPObject


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
