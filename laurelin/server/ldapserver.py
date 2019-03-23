import asyncio
import logging
import ssl
import traceback

from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError
from laurelin.ldap import rfc4511
from laurelin.ldap.net import parse_host_uri, host_port
from laurelin.ldap.constants import Scope

from . import search_results
from .dn import parse_dn
from .exceptions import *
from .backend import AbstractBackend
from .config import Config

logger = logging.getLogger('laurelin.server')


def pack(message_id, op, controls=None):
    lm = rfc4511.LDAPMessage()
    lm.setComponentByName('messageID', rfc4511.MessageID(int(message_id)))
    lm.setComponentByName('protocolOp', op)
    if controls:
        lm.setComponentByName('controls', controls)
    return lm


async def send(writer, lm):
    writer.write(ber_encode(lm))
    await writer.drain()


def ldap_result(cls, result_code, matched_dn='', message=''):
    if not cls:
        raise InternalError('ldap_result cls is not set')
    res = cls()
    res.setComponentByName('resultCode', rfc4511.ResultCode(result_code))
    res.setComponentByName('matchedDN', matched_dn)
    res.setComponentByName('diagnosticMessage', message)
    return res


def protocol_op(op_name, obj):
    if not op_name:
        raise InternalError('op_name is not set')
    op = rfc4511.ProtocolOp()
    op.setComponentByName(op_name, obj)
    return op


async def send_ldap_result_message(writer, message_id, op_name, cls, result_code, matched_dn='', message='',
                                   controls=None):
    lm = pack(message_id, protocol_op(op_name, ldap_result(cls, result_code, matched_dn, message)), controls)
    await send(writer, lm)


_dn_components = {
    'searchRequest': 'baseObject',
    'modifyRequest': 'object',
    'bindRequest': 'name',
}

_request_suffixes = ('Request', 'Req')
_root_op_names = {'bind', 'unbind', 'search', 'add', 'modify', 'modDN', 'abandon', 'extended', 'compare'}

# TODO abandon wont actually work right now -
#  need a way to interrupt the async for loop in searchRequest handling
# TODO get rid of this object!
_unimplemented_ops = {'abandon', 'extended'}

_request_str = 'Request'


def _is_request(operation):
    if operation == 'extendedReq':
        return True
    if operation.endswith(_request_str):
        root_op = operation[:-len(_request_str)]
        for prefix in _root_op_names:
            if root_op == prefix:
                return True
    return False


def _root_op(operation):
    for suffix in _request_suffixes:
        operation = operation.replace(suffix, '')
    return operation


_response_suffixes = {
    'search': 'ResDone',
    'extended': 'Resp',
}


def _response_name(root_op):
    root_op += _response_suffixes.get(root_op, 'Response')
    return root_op


def _method_name(root_op):
    return root_op.replace('DN', '_dn')


def _uc_first(string):
    return string[0].upper() + string[1:]


def _rfc4511_response_class(root_op):
    if root_op == 'search':
        return rfc4511.SearchResultDone
    elif root_op == 'modDN':
        return rfc4511.ModifyDNResponse
    else:
        cls_name = _uc_first(root_op) + 'Response'
        return getattr(rfc4511, cls_name)


class LDAPServer(object):
    DEFAULT_SSL_CLIENT_VERIFY_REQUIRED = False
    DEFAULT_SSL_CLIENT_VERIFY_USE_SYSTEM_CA = True
    DEFAULT_SSL_CLIENT_VERIFY_CA_FILE = None
    DEFAULT_SSL_CLIENT_VERIFY_CA_PATH = None
    DEFAULT_SSL_CLIENT_VERIFY_CHECK_CRL = True

    RECV_BUFFER = 1024

    OID_NOTICE_OF_DISCONNECTION = '1.3.6.1.4.1.1466.20036'  # RFC 4511 sec 4.4.1

    def __init__(self, uri: str, conf: Config, dit: dict):
        self.uri = uri
        self.conf = conf
        self.dit = dit

        # Right now this is going to be the same for every LDAPServer so maybe do once in LaurelinServer
        #  BUT depending on other things it may be different for some later, so TBD
        nc = []
        dnc = []
        for dn, backend in self.dit.items():
            nc.append(str(dn))
            if backend.default:
                if not dnc:
                    dnc.append(str(dn))
                else:
                    raise ConfigError('Multiple DIT nodes marked as default')

        if not dnc and len(nc) == 1:
            dnc.append(nc[0])

        if not nc:
            raise ConfigError('No DIT nodes configured')

        self.root_dse = search_results.Entry('', {
            'namingContexts': nc,
            'defaultNamingContext': dnc,
            'supportedLDAPVersion': ['3'],
            'vendorName': ['laurelin'],
        })

    async def run(self):
        scheme, netloc = parse_host_uri(self.uri)
        if scheme == 'ldap':
            host, port = host_port(netloc, default_port=389)
            server = await asyncio.start_server(self.client, host=host, port=port)
        elif scheme == 'ldaps':
            host, port = host_port(netloc, default_port=636)
            ctx = self._create_ssl_context()
            server = await asyncio.start_server(self.client, host=host, port=port, ssl=ctx)
        elif scheme == 'ldapi':
            server = await asyncio.start_unix_server(self.client, path=netloc)
        else:
            raise ConfigError(f'Unsupported scheme {scheme}')
        async with server:
            await server.serve_forever()

    def _backend(self, dn) -> (AbstractBackend, None):
        if dn == '':
            return
        dn = parse_dn(dn)
        suffixes = list(self.dit.keys())
        suffixes.sort(key=lambda s: len(s), reverse=True)
        for suffix in suffixes:
            if dn[-len(suffix):] == suffix:
                return self.dit[suffix]
        raise NoSuchObjectError(f'Could not find a backend to handle the DN {dn}')

    async def client(self, reader, writer):
        peername = writer.get_extra_info("peername")
        logger.debug(f'{peername}: Started new client')
        buffer = b''
        while True:  # { client recv loop
            try:
                data = await reader.read(LDAPServer.RECV_BUFFER)
                if not data:
                    logger.debug(f'{peername}: Client has exited')
                    return
                buffer += data
                while len(buffer) > 0:  # { decoded request object loop
                    request, buffer = ber_decode(buffer, asn1Spec=rfc4511.LDAPMessage())
                    message_id = int(request.getComponentByName('messageID'))

                    _op = request.getComponentByName('protocolOp')
                    operation = _op.getName()
                    root_op = _root_op(operation)
                    res_name = _response_name(root_op)

                    logger.debug(f'{peername}: Received object message_id={message_id} operation={operation} '
                                 f'root_op={root_op} res_name={res_name}')

                    # TODO this is only out here to bypass the response lookup below... there's probably
                    #  a better solution
                    if operation == 'unbindRequest':
                        # TODO actually do things here
                        logger.debug(f'{peername}: Client has unbound')
                        return

                    req_obj = _op.getComponent()
                    res_cls = _rfc4511_response_class(root_op)
                    matched_dn = str(req_obj.getComponentByName(_dn_components.get(operation, 'entry')))

                    try:
                        backend = self._backend(matched_dn)

                        if not _is_request(operation):
                            raise DisconnectionProtocolError(f'Operation {operation} does not appear to be a standard '
                                                             'LDAP request')
                        elif root_op in _unimplemented_ops:
                            # TODO eliminate this condition!
                            raise LDAPError(f'{_uc_first(root_op)} operations not yet implemented')
                        elif operation == 'bindRequest':
                            # TODO actually do things here
                            logger.debug(f'{peername}: Client has bound')
                            pass
                        elif operation == 'searchRequest':
                            logger.debug(f'{peername}: Received {operation}')

                            # Handle Root DSE request
                            scope = req_obj.getComponentByName('scope')
                            if matched_dn == '' and scope == Scope.BASE:
                                logger.debug(f'{peername}: Got root DSE request')
                                lm = pack(message_id, self.root_dse.to_proto())
                                await send(writer, lm)
                                lm = pack(message_id, search_results.Done('').to_proto())
                                await send(writer, lm)
                                continue

                            try:
                                async for result in backend.search(req_obj):
                                    lm = pack(message_id, result.to_proto())  # TODO controls?
                                    await send(writer, lm)
                                logger.debug(f'{peername}: Search successfully completed')
                                continue
                            except BaseObjectNotFound as e:
                                base_dn = matched_dn
                                matched_dn = e.args[1] or '<none>'
                                unmatched = base_dn.replace(f',{matched_dn}', '')
                                raise NoSuchObjectError(f'Search base object was not found, found up to: {matched_dn} '
                                                        f'Could not find: {unmatched}')
                        elif operation == 'compareRequest':
                            logger.debug(f'{peername}: Received {operation}')
                            cmp = await backend.compare(req_obj)

                            if cmp is True:
                                result = 'compareTrue'
                            elif cmp is False:
                                result = 'compareFalse'
                            else:
                                raise InternalError('Backend returned non-boolean for compare')

                            cr = ldap_result(rfc4511.CompareResponse, result, matched_dn, 'Compare successful')
                            op = protocol_op('compareResponse', cr)
                            lm = pack(message_id, op)  # TODO controls?

                            await send(writer, lm)
                            continue
                        else:
                            # This handles all the normal methods
                            backend_method = getattr(backend, _method_name(root_op))
                            logger.debug(f'{peername}: Received {operation}')
                            await backend_method(req_obj)
                    except ResultCodeError as e:
                        logger.debug(f'{peername}: {operation} failed with result {e.RESULT_CODE}: {e}\n'
                                     f'{traceback.format_exc()}')
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, e.RESULT_CODE, matched_dn,
                                                       str(e))
                    except LDAPError as e:
                        logger.error(f'{peername}: Sending error for {e.__class__.__name__}: {e}\n{traceback.format_exc()}')
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, 'other', message=str(e))
                    except PyAsn1Error:
                        raise
                    except (Exception, InternalError) as e:
                        logger.error(f'{peername}: Got {e.__class__.__name__}: {e}\n{traceback.format_exc()}')
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, 'other', matched_dn,
                                                       'Internal server error')
                    else:
                        logger.debug(f'{peername}: {operation} successful')
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, 'success', matched_dn)
                # } end `while len(buffer) > 0` decoded request object loop
            except SubstrateUnderrunError:
                continue
            except (PyAsn1Error, DisconnectionProtocolError) as e:
                logger.error(f'{peername}: Got fatal disconnect error {e.__class__.__name__}: {e}\n{traceback.format_exc()}')
                xr = ldap_result(rfc4511.ExtendedResponse, 'protocolError', message=str(e))
                xr.setComponentByName('responseName', LDAPServer.OID_NOTICE_OF_DISCONNECTION)
                op = protocol_op('extendedResp', xr)
                lm = pack(0, op)
                await send(writer, lm)
                return
        # } end `while True` client recv loop

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
