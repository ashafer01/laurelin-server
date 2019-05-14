"""
In-memory ephemeral LDAP backend store
"""
import logging
from laurelin.ldap.constants import Scope, DerefAliases
from laurelin.ldap.filter import parse as parse_filter
from laurelin.ldap.protoutils import split_unescaped, seq_to_list

from .ldapobject import LDAPObject
from .. import search_results
from ..backend import DataBackend
from ..dn import parse_rdn
from ..exceptions import *
from ..utils import require_component, str_component

logger = logging.getLogger('laurelin.server.memory_backend')


class MemoryBackend(DataBackend):
    def __init__(self, suffix, conf):
        DataBackend.__init__(self, suffix, conf)
        self._dit = LDAPObject(suffix)

    async def search_params(self, base_dn, scope, fil=None, attrs=None, deref_aliases=None, types_only=False,
                            limit=None, time_limit=None):
        if limit is not None or time_limit is not None:
            raise InternalError('MemoryBackend does not implement search limits')

        if base_dn == '' and scope == Scope.BASE:
            raise InternalError('Root DSE search request was dispatched to backend')

        if fil is not None:
            fil = parse_filter(fil)

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

        deref_search = (deref_aliases == DerefAliases.SEARCH or deref_aliases == DerefAliases.ALWAYS)
        for item in result_gen:
            if deref_search:
                item = self.deref_object(item)
            yield item.to_result(attrs, types_only)
        yield search_results.Done(base_obj.dn_str)

    def deref_object(self, obj: LDAPObject):
        try:
            while obj.attrs.get_attr('objectClass') == 'alias':
                aliased_dn = obj.attrs['aliasedObjectName'][0]
                obj = self._dit.get(aliased_dn)
            return obj
        except (KeyError, IndexError):
            raise AliasError(f'Alias object {obj.dn_str} is missing an aliasedObjectName attribute')
        except ObjectNotFound:
            raise AliasError(f'Aliased object {aliased_dn} does not exist')

    async def compare_params(self, dn, attr_type, attr_value):
        obj = self._dit.get(dn)
        return attr_type in obj.attrs and attr_value in obj.attrs[attr_type]

    async def modify(self, modify_request):
        dn = require_component(modify_request, 'object', str)
        changes = require_component(modify_request, 'changes')
        obj = self._dit.get(dn)
        for i in range(len(changes)):
            change = changes.getComponentByPosition(i)
            op = change.getComponentByName('operation')
            mod = change.getComponentByName('modification')
            attr_type = str(mod.getComponentByName('type'))
            attr_vals = seq_to_list(mod.getComponentByName('vals'))
            obj.modify_op(op, attr_type, attr_vals)

    async def modify_params(self, dn, mod_list):
        obj = self._dit.get(dn)
        for op, attr_type, attr_vals in mod_list:
            obj.modify_op(op, attr_type, attr_vals)

    def _get_rdn_and_parent(self, dn):
        rdn, parent_dn = split_unescaped(dn, ',', 1)
        parent_obj = self._dit.get(parent_dn)
        return parse_rdn(rdn), parent_obj

    async def add_params(self, dn, attrs):
        rdn, parent_obj = self._get_rdn_and_parent(dn)
        parent_obj.add_child(rdn, attrs)

    async def delete(self, delete_request):
        dn = str(delete_request)
        rdn, parent_obj = self._get_rdn_and_parent(dn)
        parent_obj.delete_child(rdn)

    async def mod_dn_params(self, dn, new_rdn, del_old_rdn_attr, new_parent=None):
        rdn, parent_obj = self._get_rdn_and_parent(dn)
        if new_parent:
            new_parent_obj = self._dit.get(str(_new_parent))
            obj = parent_obj.get_child(rdn)
            parent_obj.del_child_ref(rdn)
            new_parent_obj.add_child_ref(obj)
            parent_obj = new_parent_obj
        parent_obj.mod_rdn(rdn, new_rdn, del_old_rdn_attr)
