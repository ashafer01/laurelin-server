class LDAPError(Exception):
    pass


class LDAPWarning(Warning):
    pass


class SchemaError(LDAPError):
    pass


class InvalidSchemaError(SchemaError):
    pass


class SchemaLoadError(SchemaError):
    pass


class SchemaValidationError(SchemaError):
    pass


class UndefinedSchemaElementError(SchemaError):
    pass


class SyntaxParseError(LDAPError):
    pass
