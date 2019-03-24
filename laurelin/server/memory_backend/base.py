"""
In-memory ephemeral LDAP backend store
"""
import logging
from laurelin.ldap.constants import Scope, DerefAliases
from laurelin.ldap.protoutils import split_unescaped

from .ldapobject import LDAPObject
from .. import search_results
from ..backend import AbstractBackend
from ..dn import parse_rdn
from ..exceptions import *
from ..utils import raw_component, bool_component, list_component, require_component

logger = logging.getLogger('laurelin.server.memory_backend')


class MemoryBackend(AbstractBackend):
    def __init__(self, suffix, conf):
        AbstractBackend.__init__(self, suffix, conf)
        self._dit = LDAPObject(suffix)

    async def search(self, search_request):
        base_dn = str(require_component(search_request, 'baseObject'))
        scope = require_component(search_request, 'scope')

        if base_dn == '' and scope == Scope.BASE:
            raise InternalError('Root DSE search request was dispatched to backend')

        fil = raw_component(search_request, 'filter')
        attrs = list_component(search_request, 'attributes')
        types_only = bool_component(search_request, 'typesOnly', default=False)
        deref_aliases = raw_component(search_request, 'derefAliases')

        base_obj = self._dit.get(base_dn)
        if deref_aliases == DerefAliases.BASE or deref_aliases == DerefAliases.ALWAYS:
            base_obj = self.deref_object(base_obj)
        if scope == Scope.BASE:
            if base_obj.matches_filter(fil):
                yield base_obj.to_result(attrs, types_only)
            yield search_results.Done(base_obj.dn_str)
            return
        elif scope == Scope.ONE:
            result_gen = base_obj.onelevel(fil)
        elif scope == Scope.SUB:
            result_gen = base_obj.subtree(fil)
        else:
            raise ValueError('scope')

        async for item in result_gen:
            if deref_aliases == DerefAliases.SEARCH or deref_aliases == DerefAliases.ALWAYS:
                item = self.deref_object(item)
            yield item.to_result(attrs, types_only)
        yield search_results.Done(base_obj.dn_str)

    def deref_object(self, obj: LDAPObject):
        while obj.attrs.get_attr('objectClass') == 'alias':
            obj = self._dit.get(obj.attrs['aliasedObjectName'][0])
        return obj

    async def compare(self, compare_request):
        dn = require_component(compare_request, 'entry', str)
        ava = require_component(compare_request, 'ava')
        attr_type = require_component(ava, 'attributeDesc', str)
        attr_value = require_component(ava, 'assertionValue', str)  # TODO binary support

        obj = self._dit.get(dn)
        return attr_type in obj.attrs and attr_value in obj.attrs[attr_type]

    async def modify(self, modify_request):
        dn = require_component(modify_request, 'object', str)
        changes = require_component(modify_request, 'changes')
        obj = self._dit.get(dn)
        obj.modify(changes)

    def _get_rdn_and_parent(self, dn):
        rdn, parent_dn = split_unescaped(dn, ',', 1)
        parent_obj = self._dit.get(parent_dn)
        return parse_rdn(rdn), parent_obj

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

        rdn, parent_obj = self._get_rdn_and_parent(dn)
        parent_obj.add_child(rdn, attrs)

    async def delete(self, delete_request):
        dn = str(delete_request)
        rdn, parent_obj = self._get_rdn_and_parent(dn)
        parent_obj.delete_child(rdn)

    async def mod_dn(self, mod_dn_request):
        dn = require_component(mod_dn_request, 'entry', str)
        new_rdn = require_component(mod_dn_request, 'newrdn', str)
        del_old_rdn_attr = require_component(mod_dn_request, 'deleteoldrdn', bool)
        _new_parent = mod_dn_request.getComponentByName('newSuperior')

        rdn, parent_obj = self._get_rdn_and_parent(dn)
        if _new_parent.isValue:
            new_parent_obj = self._dit.get(str(_new_parent))
            obj = parent_obj.get_child(rdn)
            parent_obj.del_child_ref(rdn)
            new_parent_obj.add_child_ref(obj)
            parent_obj = new_parent_obj
        parent_obj.mod_rdn(rdn, new_rdn, del_old_rdn_attr)
