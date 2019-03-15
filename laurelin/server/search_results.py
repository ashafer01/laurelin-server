from laurelin.ldap import rfc4511


class Entry(object):
    def __init__(self, dn: str, attrs_dict: dict):
        self.dn = dn
        self.attrs = attrs_dict
        # TODO controls?

    def to_proto(self):
        op = rfc4511.ProtocolOp()
        res = rfc4511.SearchResultEntry()
        res.setComponentByName('objectName', rfc4511.LDAPDN(self.dn))
        attrs = rfc4511.PartialAttributeList()
        j = 0
        for attr, vals in self.attrs.items():
            _attr = rfc4511.PartialAttribute()
            _attr.setComponentByName('type', rfc4511.AttributeDescription(attr))
            _vals = rfc4511.Vals()
            for i, val in enumerate(vals):
                _vals.setComponentByPosition(i, rfc4511.AttributeValue(val))
            attrs.setComponentByPosition(j, _attr)
            j += 1
        res.setComponentByName('attributes', attrs)
        op.setComponentByName('searchResultEntry', res)
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
        srd.setComponentByName('resultCode', rfc4511.ResultCode('success'))
        srd.setComponentByName('matchedDN', self.matched_dn)
        srd.setComponentByName('diagnosticMessage', self.message)
        op.setComponentByName('searchResultDone', srd)
        return op
