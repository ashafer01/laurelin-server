from laurelin.ldap import rfc4511
from laurelin.ldap import Mod

from . import search_results
from .dit import DIT


class InternalClient(object):
    def __init__(self, dit: DIT):
        self.dit = dit

    async def search(self, base_dn: str, scope: rfc4511.Scope, fil: str = None,
                     attrs: list = None, deref_aliases: rfc4511.DerefAliases = None, types_only: bool = False,
                     limit: int = 0, time_limit: int = 0):
        backend = self.dit.backend(base_dn)
        search = backend.search_params(base_dn, scope, fil, attrs, deref_aliases, types_only, limit, time_limit)
        async for res in search:
            if isinstance(res, search_results.Done):
                break
            yield res

    async def compare(self, dn, attr_type, attr_value):
        backend = self.dit.backend(dn)
        return backend.compare_params(dn, attr_type, attr_value)

    async def add(self, dn: str, attrs: dict):
        backend = self.dit.backend(dn)
        return backend.add_params(dn, attrs)

    async def modify(self, dn, mod_list):
        backend = self.dit.backend(dn)
        return backend.modify_params(dn, mod_list)

    async def mod_dn(self, dn, new_rdn, del_old_rdn_attr, new_parent=None):
        backend = self.dit.backend(dn)
        return backend.mod_dn_params(dn, new_rdn, del_old_rdn_attr, new_parent)

    async def delete(self, dn):
        backend = self.dit.backend(dn)
        return backend.delete(dn)

    async def add_attrs(self, dn, attr_type, attr_vals):
        backend = self.dit.backend(dn)
        return backend.modify_params(dn, [(Mod.ADD, attr_type, attr_vals)])

    async def replace_attrs(self, dn, attr_type, attr_vals):
        backend = self.dit.backend(dn)
        return backend.modify_params(dn, [(Mod.REPLACE, attr_type, attr_vals)])

    async def delete_attrs(self, dn, attr_type, attr_vals):
        backend = self.dit.backend(dn)
        return backend.modify_params(dn, [(Mod.DELETE, attr_type, attr_vals)])
