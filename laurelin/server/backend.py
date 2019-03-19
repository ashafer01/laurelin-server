class AbstractBackend(object):
    def __init__(self, suffix, conf):
        self.suffix = suffix
        self.conf = conf
        self.default = self.conf.get('default', False)

    async def search(self, search_request):
        yield NotImplemented()

    async def compare(self, compare_request):
        raise NotImplemented()

    async def modify(self, modify_request):
        raise NotImplemented()

    async def add(self, add_request):
        raise NotImplemented()

    async def delete(self, delete_request):
        raise NotImplemented()

    async def mod_dn(self, mod_dn_request):
        raise NotImplemented()
