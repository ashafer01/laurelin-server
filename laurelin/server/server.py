import asyncio
import ssl

from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError
from laurelin.ldap import rfc4511
from laurelin.ldap.net import parse_host_uri

from .exceptions import *


def pack(message_id, op, controls=None):
    lm = rfc4511.LDAPMessage()
    lm.setComponentByName('messageID', rfc4511.MessageID(int(message_id)))
    lm.setComponentByName('protocolOp', op)
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
}

_request_suffixes = {'Request', 'Req'}
_root_op_names = {'bind', 'unbind', 'search', 'add', 'modify', 'modDN', 'abandon', 'extended', 'compare'}

# TODO abandon wont actually work right now -
#  need a way to interrupt the async for loop in searchRequest handling
# TODO get rid of this object!
_unimplemented_ops = {'bind', 'unbind', 'abandon', 'extended'}


def _is_request(operation):
    if operation == 'extendedReq':
        return True
    if operation.endswith('Request'):
        for prefix in _root_op_names:
            if operation.startswith(prefix):
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
    if root_op == 'modDN':
        cls_name = 'ModifyDNResponse'
    else:
        cls_name = _uc_first(root_op) + 'Response'
    return getattr(rfc4511, cls_name)


class LDAPServer(object):
    DEFAULT_LISTEN_URIS = ['ldap://0.0.0.0:389', 'ldapi:///var/run/laurelin-server.socket']
    DEFAULT_SSL_CLIENT_VERIFY_USE_SYSTEM_CA = True
    DEFAULT_SSL_CLIENT_VERIFY_CA_FILE = None
    DEFAULT_SSL_CLIENT_VERIFY_CA_PATH = None

    RECV_BUFFER = 1024

    OID_NOTICE_OF_DISCONNECTION = '1.3.6.1.4.1.1466.20036'  # RFC 4511 sec 4.4.1

    def __init__(self, listen_uris=None):
        if listen_uris is None:
            listen_uris = LDAPServer.DEFAULT_LISTEN_URIS

        self.listen_uris = listen_uris

        self.runners = []

        # TODO make configurable obviously
        from .memory_backend import MemoryBackend
        self.backend = MemoryBackend('o=laurelin')

    async def start(self):
        for uri in self.listen_uris:
            scheme, netloc = parse_host_uri(uri)
            if scheme == 'ldap':
                hp = netloc.rsplit(':', 1)
                host = hp[0]
                if len(hp) < 2:
                    port = 389
                else:
                    port = int(hp[1])
                await self._create_server(host=host, port=port)
            elif scheme == 'ldaps':
                hp = netloc.rsplit(':', 1)
                host = hp[0]
                if len(hp) < 2:
                    port = 636
                else:
                    port = int(hp[1])

                # TODO load configs and use them to populate
                cert_filename = ''
                private_key_filename = None
                client_verify_use_system_ca = LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_USE_SYSTEM_CA
                client_verify_ca_file = LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_CA_FILE
                client_verify_ca_path = LDAPServer.DEFAULT_SSL_CLIENT_VERIFY_CA_PATH

                ctx = self._create_ssl_context(cert_filename, private_key_filename, client_verify_use_system_ca,
                                               client_verify_ca_file, client_verify_ca_path)

                await self._create_server(host=host, port=port, ssl=ctx)
            elif scheme == 'ldapi':
                await self._create_server(path=netloc)
            else:
                raise LDAPError(f'Unsupported scheme {scheme}')

        await asyncio.gather(*self.runners)

    async def _create_server(self, path=None, host=None, port=None, ssl=None):
        kwds = {'ssl': ssl, 'start_serving': False}
        if path is not None:
            server = await asyncio.start_unix_server(self.client, path=path, **kwds)
        else:
            server = await asyncio.start_server(self.client, host=host, port=port, **kwds)
        self.runners.append(server.serve_forever())

    async def client(self, reader, writer):
        buffer = b''
        while True:  # {
            try:
                data = await reader.read(LDAPServer.RECV_BUFFER)
                buffer += data
                while len(buffer) > 0:  # {
                    request, buffer = ber_decode(buffer, asn1Spec=rfc4511.LDAPMessage())
                    message_id = int(request.getComponentByName('messageID'))

                    _op = request.getComponentByName('protocolOp')
                    operation = _op.getName()
                    root_op = _root_op(operation)
                    req_obj = _op.getComponent()

                    res_name = _response_name(root_op)
                    res_cls = _rfc4511_response_class(root_op)
                    matched_dn = str(req_obj.getComponentByName(_dn_components.get(operation, 'entry')))

                    try:
                        if not _is_request(operation):
                            raise DisconnectionProtocolError(f'Operation {operation} does not appear to be a standard '
                                                             f'LDAP request')
                        elif root_op in _unimplemented_ops:
                            raise LDAPError(f'{_uc_first(root_op)} operations not yet implemented')
                        elif operation == 'searchRequest':
                            try:
                                async for result in self.backend.search(req_obj):
                                    lm = pack(message_id, result.to_proto())  # TODO controls?
                                    await send(writer, lm)
                            except BaseObjectNotFound as e:
                                base_dn = matched_dn
                                matched_dn = e.args[1] or '<none>'
                                unmatched = base_dn.replace(f',{matched_dn}', '')
                                raise NoSuchObjectError(f'Search base object was not found, found up to: {matched_dn} '
                                                        f'Could not find: {unmatched}')
                        elif operation == 'compareRequest':
                            cmp = await self.backend.compare(req_obj)

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
                            await getattr(self.backend, _method_name(root_op))(req_obj)
                    except ResultCodeError as e:
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, e.RESULT_CODE, matched_dn,
                                                       str(e))
                    except LDAPError as e:
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, 'other', message=str(e))
                    except (Exception, InternalError):
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, 'other', matched_dn,
                                                       'Unhandled exception during modify')
                    else:
                        await send_ldap_result_message(writer, message_id, res_name, res_cls, 'success', matched_dn)
                # } end `while len(buffer) > 0` decoded request object loop
            except SubstrateUnderrunError:
                continue
            except (PyAsn1Error, DisconnectionProtocolError) as e:
                xr = ldap_result(rfc4511.ExtendedResponse, 'protocolError', message=str(e))
                xr.setComponentByName('responseName', LDAPServer.OID_NOTICE_OF_DISCONNECTION)
                op = protocol_op('extendedResp', xr)
                lm = pack(0, op)
                await send(writer, lm)
                writer.close()
                reader.close()
                break
        # } end `while True` client recv loop

    @staticmethod
    def _create_ssl_context(cert_filename, private_key_filename, client_verify_use_system_ca, client_verify_ca_file,
                            client_verify_ca_path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_filename, private_key_filename)
        if client_verify_use_system_ca:
            ctx.load_default_certs(ssl.Purpose.CLIENT_AUTH)
        if client_verify_ca_file or client_verify_ca_path:
            ctx.load_verify_locations(client_verify_ca_file, client_verify_ca_path)
        return ctx
