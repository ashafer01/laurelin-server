from .base import BaseSchemaElement, schema
from ..exceptions import *


class ObjectClass(BaseSchemaElement):
    def __init__(self, params):
        params.setdefault('obsolete', False)
        params.setdefault('type', 'structural')
        BaseSchemaElement.__init__(self, params)
        self.required_attrs = {attr.lower() for attr in self['required_attributes']}
        self.allowed_attrs = {attr.lower() for attr in self['allowed_attributes']}
        self.resolved = False

    def merge(self, object_class):
        """Combine another ObjectClass with this one, returning a new ObjectClass"""
        new_oc = ObjectClass(self._params)
        other_oc = schema.get_object_class(object_class)
        new_oc.required_attrs |= other_oc.required_attrs
        new_oc.allowed_attrs |= other_oc.allowed_attrs
        return new_oc

    def resolve(self):
        if not self.resolved and 'inherits' in self:
            try:
                superclass = schema.get_object_class(self['inherits'])
            except KeyError:
                raise InvalidSchemaError(f'superclass {self["inherits"]} for {self["name"]} does not exist')
            superclass.resolve()
            self.required_attrs |= superclass.required_attrs
            self.allowed_attrs |= superclass.allowed_attrs
        self.resolved = True

    def validate(self, attrs: dict):
        """Ensure a dictionary of attributes conforms to this ObjectClass"""
        attr_types_set = {attr.lower() for attr in attrs.keys()}

        missing_required = self.required_attrs - attr_types_set
        if missing_required:
            missing_required = ', '.join(missing_required)
            raise SchemaValidationError(f'Missing required attributes: {missing_required}')

        not_required = attr_types_set - self.required_attrs
        not_allowed = not_required - self.allowed_attrs
        if not_allowed:
            not_allowed = ', '.join(not_allowed)
            raise SchemaValidationError(f'Attribute types are not allowed: {not_allowed}')

        self.attr_type_validate(attrs)

    def attr_type_validate(self, attrs: dict):
        for attr, values in attrs.items():
            attr_type = schema.get_attribute_type(attr)
            try:
                attr_type.validate(values)
            except SchemaValidationError:
                raise SchemaValidationError(f'Not a valid object class {self["name"]}')


class ExtensibleObjectClass(ObjectClass):
    def __init__(self):
        BaseSchemaElement.__init__(self, {
            'oid': '1.3.6.1.4.1.1466.101.120.111',
            'name': 'extensibleObject',
            'inherits': 'top',
            'type': 'auxiliary',
        })

    def validate(self, attrs: dict):
        for attr in attrs.keys():
            if attr['usage'] != 'userApplications':
                raise SchemaValidationError('Non-user attribute on extensibleObject')

        self.attr_type_validate(attrs)
