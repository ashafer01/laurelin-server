class AbstractBackend(object):
    def __init__(self, suffix, conf):
        self.suffix = suffix
        self.conf = conf
        self.default = self.conf.get('default', False)

    async def search(self, search_request):
        raise NotImplementedError()
        yield

    async def compare(self, compare_request):
        raise NotImplementedError()

    async def modify(self, modify_request):
        raise NotImplementedError()

    async def add(self, add_request):
        raise NotImplementedError()

    async def delete(self, delete_request):
        raise NotImplementedError()

    async def mod_dn(self, mod_dn_request):
        raise NotImplementedError()
