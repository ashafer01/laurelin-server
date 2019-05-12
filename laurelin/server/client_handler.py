import asyncio
import logging
import traceback

from async_timeout import timeout
from laurelin.ldap import rfc4511
from laurelin.ldap.constants import Scope
from pyasn1.codec.ber.decoder import decode as ber_decode
from pyasn1.codec.ber.encoder import encode as ber_encode
from pyasn1.error import PyAsn1Error, SubstrateUnderrunError

from . import search_results, constants
from .backend import AbstractBackend
from .dn import parse_dn
from .exceptions import *
from .request import Request, is_request
from .utils import require_component, int_component


def pack(message_id, op, controls=None):
    """Instantiate rfc4511.LDAPMessage using existing rfc4511.ProtocolOp and optional rfc4511.Controls"""
    lm = rfc4511.LDAPMessage()
    lm.setComponentByName('messageID', rfc4511.MessageID(int(message_id)))
    lm.setComponentByName('protocolOp', op)
    if controls:
        lm.setComponentByName('controls', controls)
    return lm


def ldap_result(cls, result_code, matched_dn='', message=''):
    """Instantiate an rfc4511 class which uses COMPONENTS OF LDAPResult"""
    if not cls:
        raise InternalError('ldap_result cls is not set')
    res = cls()
    res.setComponentByName('resultCode', rfc4511.ResultCode(result_code))
    res.setComponentByName('matchedDN', matched_dn)
    res.setComponentByName('diagnosticMessage', message)
    return res


def protocol_op(op_name: str, obj):
    """Instantiate rfc4511.ProtocolOp using the string component name and matching rfc4511 object"""
    if not op_name:
        raise InternalError('op_name is not set')
    op = rfc4511.ProtocolOp()
    op.setComponentByName(op_name, obj)
    return op


def _backend_method_name(root_op: str):
    """Convert a root operation string to the name of a method on an AbstractBackend"""
    return root_op.replace('DN', '_dn')


def _handler_method_name(root_op: str):
    """Convert a root operation string to the name of a method on ClientHandler"""
    return '_handle_' + root_op


class ClientLogger(object):
    """Proxy logger that prefixes log messages with a client identifier"""

    def __init__(self, peername):
        self._peername = peername
        self._logger = logging.getLogger('laurelin.server.client_handler')

    def __getattr__(self, item):
        log_func = getattr(self._logger, item)

        def log(msg):
            return log_func(f'{self._peername}: {msg}')

        return log

    def exception(self, msg, e):
        self.error(f'{msg}: {e.__class__.__name__}: {e}\n{traceback.format_exc()}')


class ClientHandler(object):
    RECV_BUFFER = 1024

    def __init__(self, reader, writer, dit):
        self.reader = reader
        self.writer = writer
        self.dit = dit
        self.log = ClientLogger(writer.get_extra_info('peername'))

        # Right now this is going to be the same for every client so maybe do once in LaurelinServer/LDAPServer
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

        # sorted list of DIT suffixes - most RDNs first, otherwise order does not matter
        self.suffixes = list(self.dit.keys())
        self.suffixes.sort(key=lambda s: len(s), reverse=True)

        self.root_dse = search_results.Entry('', {
            'namingContexts': nc,
            'defaultNamingContext': dnc,
            'supportedLDAPVersion': ['3'],
            'vendorName': ['laurelin'],
        })

    def _backend(self, dn) -> (AbstractBackend, None):
        """Obtain the backend for a given DN"""
        if dn == '':
            return
        dn = parse_dn(dn)
        for suffix in self.suffixes:
            if dn[-len(suffix):] == suffix:
                return self.dit[suffix]
        raise NoSuchObjectError(f'Could not find a backend to handle the DN {dn}')

    async def send(self, lm: rfc4511.LDAPMessage):
        """Encode and send an LDAP message"""
        self.writer.write(ber_encode(lm))
        await self.writer.drain()

    async def send_ldap_result(self, req: Request, result_code, message='', controls=None):
        """Prepare and send an LDAP result message appropriate to the given Request"""
        res = ldap_result(req.res_cls, result_code, req.matched_dn, message)
        po = protocol_op(req.res_name, res)
        lm = pack(req.id, po, controls)
        await self.send(lm)

    async def run(self):
        """Handle the client's requests forever"""

        self.log.debug('Started new client')
        buffer = b''
        while True:
            try:
                data = await self.reader.read(self.RECV_BUFFER)
                if not data:
                    self.log.info('Client has exited')
                    return
                buffer += data
                while len(buffer) > 0:
                    _request, buffer = ber_decode(buffer, asn1Spec=rfc4511.LDAPMessage())
                    req = Request(_request)

                    self.log.info(f'Received message_id={req.id} operation={req.operation}')

                    if req.operation == 'unbindRequest':
                        # TODO actually unbind
                        self.log.info('Client has unbound')
                        return
                    elif req.operation == 'abandonRequest':
                        # As of right now I can't fathom a way to actually get abandon to work with asyncio
                        #
                        # Unfortunately RFC4511 specifies that interrupting result entries is the one thing we MUST
                        # do, but it also says clients MUST NOT care if the abandon worked, so ... ?
                        self.log.warning('Received abandon request - ignoring')
                    else:
                        await self._respond_to_request(req)
            except SubstrateUnderrunError:
                continue
            except (PyAsn1Error, DisconnectionProtocolError) as e:
                self.log.exception('Caught fatal disconnect error', e)
                xr = ldap_result(rfc4511.ExtendedResponse, 'protocolError', message=str(e))
                xr.setComponentByName('responseName', constants.OID_NOTICE_OF_DISCONNECTION)
                op = protocol_op('extendedResp', xr)
                lm = pack(0, op)
                await self.send(lm)
                return

    async def _respond_to_request(self, req):
        if not is_request(req.operation):
            raise DisconnectionProtocolError(f'{req.id} does not appear to contain a standard LDAP request')

        try:
            req.populate_response_attrs()
            handler_method = getattr(self, _handler_method_name(req.root_op), self._handle_generic)
            await handler_method(req)
        except ResultCodeError as e:
            self.log.info(f'{req.operation} {req.id} failed gracefully with result {e.RESULT_CODE}: '
                          f'{e}\n{traceback.format_exc()}')
            await self.send_ldap_result(req, e.RESULT_CODE, str(e))
        except LDAPError as e:
            self.log.exception(f'{req.operation} {req.id} Sending error response due to', e)
            await self.send_ldap_result(req, 'other', message=str(e))
        except PyAsn1Error:
            raise
        except (Exception, InternalError) as e:
            self.log.exception(f'{req.operation} {req.id} exception', e)
            await self.send_ldap_result(req, 'other', 'Internal server error')

    async def _handle_generic(self, req):
        # This handles all the normal methods
        backend_method = getattr(self._backend(req.matched_dn), _backend_method_name(req.root_op))
        self.log.info(f'Received {req.operation}')
        await backend_method(req.asn1_obj)
        self.log.debug(f'{req.operation} {req.id} successful')
        await self.send_ldap_result(req, 'success')

    async def _handle_bind(self, req):
        # TODO bind for real
        await self.send_ldap_result(req, 'success')
        bind_name = require_component(req, 'name', str)
        auth_choice = require_component(req, 'authentication')
        auth_type = auth_choice.getName()
        if auth_type == 'simple':
            pass
        elif auth_type == 'sasl':
            pass
        else:
            raise AuthMethodNotSupportedError(f'Authentication method "{auth_type}" is not supported')
        self.log.info('Client has bound')

    async def _handle_search(self, req):
        # Handle Root DSE request
        scope = require_component(req.asn1_obj, 'scope')
        if req.matched_dn == '' and scope == Scope.BASE:
            self.log.debug('Got root DSE request')
            lm = pack(req.id, self.root_dse.to_proto())
            await self.send(lm)
            lm = pack(req.id, search_results.Done('').to_proto())
            await self.send(lm)
            return

        limit = int_component(req.asn1_obj, 'sizeLimit', default_value=0)
        time_limit = int_component(req.asn1_obj, 'timeLimit', default_value=0)

        try:
            n = 0
            async with timeout(time_limit):
                async for result in self._backend(req.matched_dn).search(req.asn1_obj):
                    lm = pack(req.id, result.to_proto())  # TODO controls?
                    await self.send(lm)
                    n += 1
                    if limit and n >= limit:
                        self.log.debug(f'Search {req.id} hit requested size limit')
                        break
            self.log.debug('Search successfully completed')
        except ObjectNotFound as e:
            base_dn = req.matched_dn
            matched_dn = e.args[1] or '<none>'
            unmatched = base_dn.replace(f',{matched_dn}', '')
            raise NoSuchObjectError(f'Search base object was not found, found up to: {matched_dn} '
                                    f'Could not find: {unmatched}')
        except asyncio.TimeoutError:
            raise TimeLimitExceededError(f'Requested time limit of {time_limit} seconds was '
                                         'exceeded during search request')

    async def _handle_compare(self, req):
        cmp = await self._backend(req.matched_dn).compare(req.asn1_obj)

        if cmp is True:
            result = 'compareTrue'
        elif cmp is False:
            result = 'compareFalse'
        else:
            raise InternalError('Backend returned non-boolean for compare')

        cr = ldap_result(rfc4511.CompareResponse, result, 'Compare successful')
        op = protocol_op('compareResponse', cr)
        lm = pack(req.id, op)  # TODO controls?

        await self.send(lm)

    async def _handle_extended(self, req):
        # TODO extended requests
        raise LDAPError(f'Extended operations not yet implemented')
