from laurelin.ldap import rfc4511

from .attrsdict import AttrsDict


class Entry(object):
    def __init__(self, dn: str, attrs_dict: dict):
        self.dn = dn
        if isinstance(attrs_dict, AttrsDict):
            self.attrs = attrs_dict
        else:
            self.attrs = AttrsDict(attrs_dict)
        # TODO controls?

    def to_proto(self):
        op = rfc4511.ProtocolOp()
        res = rfc4511.SearchResultEntry()
        res.setComponentByName('objectName', rfc4511.LDAPDN(self.dn))
        attrs = rfc4511.PartialAttributeList()
        j = 0
        for attr, vals in self.attrs.items():
            if not vals:
                continue
            _attr = rfc4511.PartialAttribute()
            _attr.setComponentByName('type', rfc4511.AttributeDescription(attr))
            _vals = rfc4511.Vals()
            for i, val in enumerate(vals):
                _vals.setComponentByPosition(i, rfc4511.AttributeValue(val))
            _attr.setComponentByName('vals', _vals)
            attrs.setComponentByPosition(j, _attr)
            j += 1
        res.setComponentByName('attributes', attrs)
        op.setComponentByName('searchResEntry', res)
        return op


class Done(object):
    def __init__(self, matched_dn, result_code=None, message=None):
        if result_code is None:
            result_code = rfc4511.ResultCode('success')
        if message is None:
            message = 'Search successful'

        self.matched_dn = matched_dn
        self.result_code = result_code
        self.message = message
        # TODO controls?

    def to_proto(self):
        op = rfc4511.ProtocolOp()
        srd = rfc4511.SearchResultDone()
        srd.setComponentByName('resultCode', self.result_code)
        srd.setComponentByName('matchedDN', self.matched_dn)
        srd.setComponentByName('diagnosticMessage', self.message)
        op.setComponentByName('searchResDone', srd)
        return op
