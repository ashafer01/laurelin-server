from laurelin.ldap.utils import CaseIgnoreDict


class AttrsDict(CaseIgnoreDict):
    def get_attr(self, attr):
        """Get an attribute's values, or an empty list if the attribute is not defined

        :param attr: The name of the attribute
        :return: A list of values
        :rtype: list
        """
        return self.get(attr, [])

    def deepcopy(self, attrs=None):
        """Return a deep copy of self optionally limited to attrs"""
        ret = AttrsDict()
        for attr, vals in self.items():
            if attrs and attr not in attrs:
                continue
            ret[attr] = []
            for val in vals:
                ret[attr].append(val)
        return ret

    # dict overrides for case-insensitive keys and enforcing types

    def __init__(self, attrs_dict=None):
        CaseIgnoreDict.__init__(self, attrs_dict)

    def __contains__(self, attr):
        try:
            return len(self[attr]) > 0
        except KeyError:
            return False

    def __setitem__(self, attr, values):
        self.enforce_attr_type(attr)
        self.enforce_values_type(values)
        CaseIgnoreDict.__setitem__(self, attr, values)

    def setdefault(self, attr, default=None):
        self.enforce_attr_type(attr)
        if default is None:
            default = []
        try:
            self.enforce_values_type(default)
        except TypeError as e:
            raise TypeError('invalid default - {0}'.format(str(e)))
        return CaseIgnoreDict.setdefault(self, attr, default)

    def update(self, attrs_dict):
        self.enforce_dict_type(attrs_dict)
        CaseIgnoreDict.update(self, attrs_dict)

    @staticmethod
    def enforce_dict_type(attrs_dict):
        """Validate that ``attrs_dict`` is either already an :class:`.AttrsDict` or that it conforms to the required
        ``dict(str, list[str or bytes])`` typing.

        :param dict attrs_dict: The dictionary to validate for use as an attributes dictionary
        :rtype: None
        :raises TypeError: when the dict is invalid
        """
        if isinstance(attrs_dict, AttrsDict):
            return
        if not isinstance(attrs_dict, dict):
            raise TypeError('must be dict')
        for attr in attrs_dict:
            AttrsDict.enforce_attr_type(attr)
            AttrsDict.enforce_values_type(attrs_dict[attr])

    @staticmethod
    def enforce_attr_type(attr):
        """Validate that ``attr`` is a valid attribute name.

        :param str attr: The string to validate for use as an attribute name
        :rtype: None
        :raises TypeError: when the string is invalid
        """
        if not isinstance(attr, str):
            raise TypeError('attribute name must be string')

    @staticmethod
    def enforce_values_type(attr_val_list):
        """Validate that ``attr_val_list`` conforms to the required ``list[str or bytes]`` typing.

        :param list attr_val_list: The list to validate for use as an attribute value list.
        :rtype: None
        :raises TypeError: when the list is invalid
        """
        if not isinstance(attr_val_list, list):
            raise TypeError('must be list')
        for val in attr_val_list:
            if not isinstance(val, str) and not isinstance(val, bytes):
                raise TypeError('attribute values must be string or bytes')
