from laurelin.ldap.protoutils import seq_to_list
from pyasn1.error import PyAsn1Error


def get_component(asn1_obj, component_ident):
    if isinstance(component_ident, str):
        return asn1_obj.getComponentByName(component_ident)
    elif isinstance(component_ident, int):
        return asn1_obj.getComponentByPosition(component_ident)
    else:
        raise TypeError('component_ident must be string or int')


def _cast_value(val, val_type):
    if val_type is None:
        return val
    else:
        return val_type(val)


def optional_component(asn1_obj, component_ident, default=None, val_type=None):
    try:
        _val = get_component(asn1_obj, component_ident)
    except PyAsn1Error:
        return default
    if _val.isValue:
        return _cast_value(_val, val_type)
    else:
        return default


def str_component(asn1_obj, component_ident, default=None):
    return optional_component(asn1_obj, component_ident, default, str)


def bool_component(asn1_obj, component_ident, default=None):
    return optional_component(asn1_obj, component_ident, default, bool)


def int_component(asn1_obj, component_ident, default=None, default_value=0):
    val = optional_component(asn1_obj, component_ident, default, int)
    if default_value is not None and val == default_value:
        return default
    else:
        return val


def list_component(asn1_obj, component_ident, default=None):
    if default is None:
        default = []
    return optional_component(asn1_obj, component_ident, default, seq_to_list)


def require_component(asn1_obj, component_ident, val_type=None):
    val = get_component(asn1_obj, component_ident)
    if val.isValue:
        return _cast_value(val, val_type)
    else:
        raise PyAsn1Error(f'Required component {component_ident} is not set to a value')
