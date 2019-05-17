import asyncio
import logging
import logging.config
from .auth import AuthStack
from .config import Config
from .dit import DIT
from .ldapserver import LDAPServer
from .schema import get_schema

_logger_name = 'laurelin.server'


class LaurelinServer(object):
    def __init__(self, conf: Config):
        self.logger = logging.getLogger(_logger_name)

        dit = DIT(conf['dit'])
        auth_stack = AuthStack(conf['auth_stack'], conf['auth_backends'], dit)

        self.servers = []
        for uri, server_conf in conf['servers'].items():
            self.logger.debug(f'Setting up LDAPServer {uri}')
            self.servers.append(LDAPServer(uri, Config(server_conf), dit, auth_stack))

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
