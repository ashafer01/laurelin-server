class LDAPError(Exception):
    pass


class SchemaValidationError(LDAPError):
    pass


class SyntaxParseError(LDAPError):
    pass
