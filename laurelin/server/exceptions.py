class LDAPError(Exception):
    pass


class InvalidSchemaError(LDAPError):
    pass


class SchemaValidationError(LDAPError):
    pass


class SyntaxParseError(LDAPError):
    pass
