from laurelin.ldap import rfc4511

from .utils import require_component

_dn_components = {
    'searchRequest': 'baseObject',
    'modifyRequest': 'object',
    'bindRequest': 'name',
}

_request_suffixes = ('Request', 'Req')


def _root_op(operation):
    """Convert a full rfc4511.ProtocolOp request name to the root operation; e.g. searchRequest -> search"""
    for suffix in _request_suffixes:
        operation = operation.replace(suffix, '')
    return operation


_response_suffixes = {
    'search': 'ResDone',
    'extended': 'Resp',
}


def _response_name(root_op):
    """Convert the result of _root_op() to the associated response operation name for the request"""
    root_op += _response_suffixes.get(root_op, 'Response')
    return root_op


def _uc_first(string):
    """Upper-case the first character of the given string"""
    return string[0].upper() + string[1:]


def _rfc4511_response_class(root_op):
    """Obtain the rfc4511 class to be used to respond to the given _root_op() result"""
    if root_op == 'search':
        return rfc4511.SearchResultDone
    elif root_op == 'modDN':
        return rfc4511.ModifyDNResponse
    else:
        cls_name = _uc_first(root_op) + 'Response'
        return getattr(rfc4511, cls_name)


class Request(object):
    """Internal representation of a user request"""

    def __init__(self, request: rfc4511.LDAPMessage):
        _op = require_component(request, 'protocolOp')
        self.id = require_component(request, 'messageID', int)
        self.operation = _op.getName()
        self.asn1_obj = _op.getComponent()
        self.root_op = _root_op(self.operation)

        # Attributes needed to respond to the request
        self.res_name = None
        self.res_cls = None
        self.matched_dn = ''

    def populate_response_attrs(self):
        """Populate the attributes needed to respond to the request"""
        # This is a separate call because not all requests have a response
        # Should not be called until we have determined that the request has a response
        self.res_name = _response_name(self.root_op)
        self.res_cls = _rfc4511_response_class(self.root_op)
        self.matched_dn = require_component(self.asn1_obj, _dn_components.get(self.operation, 'entry'), str)
