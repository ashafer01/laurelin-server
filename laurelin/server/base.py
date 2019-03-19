import asyncio
import logging
from .config import Config
from .dn import parse_dn
from .ldapserver import LDAPServer
from .schema import get_schema

# TODO probly gonna need to dynamically import backends
from .memory_backend import MemoryBackend

_backend_types = {
    'memory': MemoryBackend,
}

logger = logging.getLogger('laurelin.server')


class LaurelinServer(object):
    def __init__(self, conf: Config):
        dit = {}
        for suffix, node_conf in conf['dit'].items():
            dit[parse_dn(suffix)] = _backend_types[node_conf['data_backend']](suffix, Config(node_conf))

        self.servers = []
        for uri, server_conf in conf['servers'].items():
            logger.debug(f'Setting up LDAPServer {uri}')
            self.servers.append(LDAPServer(uri, Config(server_conf), dit))

    async def run(self):
        logger.debug('Running LaurelinServer')
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
