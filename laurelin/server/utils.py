from laurelin.ldap.protoutils import seq_to_list
from pyasn1.error import PyAsn1Error


def _get_component(asn1_obj, component_ident):
    if isinstance(component_ident, str):
        return asn1_obj.getComponentByName(component_ident)
    elif isinstance(component_ident, int):
        return asn1_obj.getComponentByPosition(component_ident)
    else:
        raise TypeError('component_ident must be string or int')


def _component_to_type(asn1_obj, component_ident, default, val_type):
    _val = _get_component(asn1_obj, component_ident)
    if _val.isValue:
        return val_type(_val)
    else:
        return default


def str_component(asn1_obj, component_ident, default=None):
    return _component_to_type(asn1_obj, component_ident, default, str)


def bool_component(asn1_obj, component_ident, default=None):
    return _component_to_type(asn1_obj, component_ident, default, bool)


def int_component(asn1_obj, component_ident, default=None, default_value=0):
    val = _component_to_type(asn1_obj, component_ident, default, int)
    if val == default_value:
        return default
    else:
        return val


def list_component(asn1_obj, component_ident, default=None):
    return _component_to_type(asn1_obj, component_ident, default, seq_to_list)


def component(asn1_obj, component_ident, default=None):
    _val = _get_component(asn1_obj, component_ident)
    if _val.isValue:
        return _val
    else:
        return default


def require_component(asn1_obj, component_ident):
    val = _get_component(asn1_obj, component_ident)
    if not val.isValue:
        raise PyAsn1Error(f'Required component {component_ident} is not set to a value')
    return val
