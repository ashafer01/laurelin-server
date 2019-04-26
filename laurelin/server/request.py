from laurelin.ldap import rfc4511

from .utils import require_component

_dn_components = {
    'searchRequest': 'baseObject',
    'modifyRequest': 'object',
    'bindRequest': 'name',
}

_request_suffixes = ('Request', 'Req')


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


class Request(object):
    def __init__(self, request):
        _op = require_component(request, 'protocolOp')
        self.id = require_component(request, 'messageID', int)
        self.operation = _op.getName()
        self.asn1_obj = _op.getComponent()
        self.root_op = _root_op(self.operation)
        self.res_name = None
        self.res_cls = None
        self.matched_dn = ''

    def populate_response_attrs(self):
        self.res_name = _response_name(self.root_op)
        self.res_cls = _rfc4511_response_class(self.root_op)
        self.matched_dn = require_component(self.asn1_obj, _dn_components.get(self.operation, 'entry'), str)
