from .element import BaseSchemaElement

from laurelin.ldap import rfc4518

prep_routines = {
    'case_exact': (
        rfc4518.Transcode,
        rfc4518.Map.characters,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.space,
    ),
    'case_ignore': (
        rfc4518.Transcode,
        rfc4518.Map.all,
        rfc4518.Normalize,
        rfc4518.Prohibit,
        rfc4518.Insignificant.space,
    )
}


# TODO make matching rules match things
class MatchingRule(BaseSchemaElement):
    pass
