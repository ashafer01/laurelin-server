import asyncio
import logging
import ssl

from laurelin.ldap.net import parse_host_uri, host_port

from .exceptions import *
from .config import Config
from .client_handler import ClientHandler

logger = logging.getLogger('laurelin.server')


class LDAPServer(object):
    DEFAULT_SSL_CLIENT_VERIFY_REQUIRED = False
    DEFAULT_SSL_CLIENT_VERIFY_USE_SYSTEM_CA = False
    DEFAULT_SSL_CLIENT_VERIFY_CA_FILE = None
    DEFAULT_SSL_CLIENT_VERIFY_CA_PATH = None
    DEFAULT_SSL_CLIENT_VERIFY_CHECK_CRL = True

    def __init__(self, uri: str, conf: Config, globals):
        self.uri = uri
        self.conf = conf
        self.G = globals
        self.server = None

    async def run(self):
        scheme, netloc = parse_host_uri(self.uri)
        if scheme == 'ldap':
            host, port = host_port(netloc, default_port=389)
            self.server = await asyncio.start_server(self.client, host=host, port=port)
        elif scheme == 'ldaps':
            host, port = host_port(netloc, default_port=636)
            ctx = self._create_ssl_context()
            self.server = await asyncio.start_server(self.client, host=host, port=port, ssl=ctx)
        elif scheme == 'ldapi':
            self.server = await asyncio.start_unix_server(self.client, path=netloc)
        else:
            raise ConfigError(f'Unsupported URI scheme {scheme}')
        async with self.server:
            await self.server.serve_forever()

    async def client(self, reader, writer):
        await ClientHandler(reader, writer, self.G).run()

    def _create_ssl_context(self):
        cert_filename = self.conf['certificate']
        private_key_filename = self.conf['private_key']
        client_verify_required = self.conf.mget('client_verify', 'required',
                                                default=LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_REQUIRED)
        client_verify_use_system_ca = self.conf.mget('client_verify', 'use_system_ca_store',
                                                     default=LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_USE_SYSTEM_CA)
        client_verify_ca_file = self.conf.mget('client_verify', 'ca_file',
                                               default=LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_CA_FILE)
        client_verify_ca_path = self.conf.mget('client_verify', 'ca_path',
                                               default=LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_CA_PATH)
        client_verify_check_crl = self.conf.mget('client_verify', 'check_crl',
                                                 default=LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_CHECK_CRL)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_filename, private_key_filename)
        if client_verify_required:
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.verify_mode = ssl.CERT_NONE
        if client_verify_check_crl:
            ctx.verify_flags = ssl.VERIFY_CRL_CHECK_CHAIN | ssl.VERIFY_X509_TRUSTED_FIRST
        if client_verify_use_system_ca:
            ctx.load_default_certs(ssl.Purpose.CLIENT_AUTH)
            if not client_verify_required:
                ctx.verify_mode = ssl.CERT_OPTIONAL
        if client_verify_ca_file or client_verify_ca_path:
            ctx.load_verify_locations(client_verify_ca_file, client_verify_ca_path)
            if not client_verify_required:
                ctx.verify_mode = ssl.CERT_OPTIONAL
        return ctx
