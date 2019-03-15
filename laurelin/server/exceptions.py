class DisconnectionProtocolError(BaseException):
    pass


class InternalError(BaseException):
    pass


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


class BaseObjectNotFound(LDAPError):
    pass


class NeededRuleError(SchemaError):
    pass


class NeededRuleUndefinedError(NeededRuleError):
    pass


class NeededRuleNotSpecifiedError(NeededRuleError):
    pass


class ResultCodeError(LDAPError):
    RESULT_CODE = 'other'


class InvalidDNError(ResultCodeError):
    RESULT_CODE = 'invalidDNSyntax'


class ProtocolError(ResultCodeError):
    RESULT_CODE = 'protocolError'


class NoSuchObjectError(ResultCodeError):
    RESULT_CODE = 'noSuchObject'


class NoSuchAttributeError(ResultCodeError):
    RESULT_CODE = 'noSuchAttribute'


class EntryAlreadyExistsError(ResultCodeError):
    RESULT_CODE = 'entryAlreadyExists'
