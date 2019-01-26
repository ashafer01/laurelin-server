class LDAPError(Exception):
    pass


class LDAPWarning(Warning):
    pass


class InvalidSchemaError(LDAPError):
    pass


class SchemaValidationError(LDAPError):
    pass


class SyntaxParseError(LDAPError):
    pass
