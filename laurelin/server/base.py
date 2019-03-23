import asyncio
import logging
import logging.config
from .config import Config
from .dn import parse_dn
from .ldapserver import LDAPServer
from .schema import get_schema

# TODO probly gonna need to dynamically import backends
from .memory_backend import MemoryBackend

_backend_types = {
    'memory': MemoryBackend,
}

_logger_name = 'laurelin.server'


class LaurelinServer(object):
    def __init__(self, conf: Config):
        self.logger = logging.getLogger(_logger_name)

        dit = {}
        for suffix, node_conf in conf['dit'].items():
            dit[parse_dn(suffix)] = _backend_types[node_conf['data_backend']](suffix, Config(node_conf))

        self.servers = []
        for uri, server_conf in conf['servers'].items():
            self.logger.debug(f'Setting up LDAPServer {uri}')
            self.servers.append(LDAPServer(uri, Config(server_conf), dit))

        self.logger.debug('LaurelinServer init complete')

    async def run(self):
        self.logger.debug('Running LaurelinServer')
        await asyncio.gather(*[server.run() for server in self.servers])


async def run_config_file(conf_fn):
    conf = Config()
    conf.load_file(conf_fn)

    logging.config.dictConfig(conf.get('logging', {'version': 1}))
    logger = logging.getLogger(_logger_name)
    logger.debug(f'Loaded config file {conf_fn}')

    schema = get_schema()
    schema.conf = Config(conf.get('schema', {}))
    schema.load_builtin()
    schema.load_conf_dir()
    schema.resolve()

    server = LaurelinServer(conf)
    await server.run()
