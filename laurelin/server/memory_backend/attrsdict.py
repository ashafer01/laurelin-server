from laurelin.ldap.utils import CaseIgnoreDict

from .attrvaluelist import AttrValueList


class AttrsDict(CaseIgnoreDict):
    def get_attr(self, attr):
        """Get an attribute's values, or an empty list if the attribute is not defined

        :param str attr: The name of the attribute
        :return: A list of values
        :rtype: AttrValueList
        """
        return self.get(attr, AttrValueList(attr))

    def deepcopy(self, attrs=None):
        """Return a deep copy of self optionally limited to attrs"""
        ret = AttrsDict()
        for attr, vals in self.items():
            if attrs:
                if attr not in attrs:
                    continue
            ret[attr] = AttrValueList(attr)
            for val in vals:
                ret[attr].append(val)
        return ret

    def setdefault(self, attr, default=None) -> AttrValueList:
        if default is None:
            default = AttrValueList(attr)
        return CaseIgnoreDict.setdefault(self, attr, default)

    def __setitem__(self, key, value):
        if isinstance(value, list):
            if not isinstance(value, AttrValueList):
                new_val = AttrValueList(key)
                new_val.extend(value)
                value = new_val
        else:
            raise TypeError('AttrsDict values must be list')
        CaseIgnoreDict.__setitem__(self, key, value)
