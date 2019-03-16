import asyncio
from .config import Config
from .ldapserver import LDAPServer
from .schema import get_schema

# TODO probly gonna need to dynamically import backends
from .memory_backend import MemoryBackend

_backend_types = {
    'memory': MemoryBackend,
}


class LaurelinServer(object):
    def __init__(self, conf: Config):
        self.conf = conf

        self.backends = {}
        for name, backend_conf in conf['backends'].items():
            self.backends[name] = _backend_types[backend_conf['type']](Config(backend_conf))

        self.servers = []
        for uri, server_conf in conf['servers'].items():
            try:
                backend_name = server_conf['use_backend']
            except KeyError:
                backend_name = conf['default_backend']
            self.servers.append(LDAPServer(uri, Config(server_conf), self.backends[backend_name]))

    async def run(self):
        await asyncio.gather(*[server.run() for server in self.servers])


async def run_config(conf_fn):
    conf = Config()
    conf.load_file(conf_fn)

    schema = get_schema()
    schema.conf = Config(conf.get('schema', {}))
    schema.load_builtin()
    schema.load_conf_dir()
    schema.resolve()

    server = LaurelinServer(conf)
    await server.run()
