class BaseSchemaElement(object):
    def __init__(self, params):
        self._params = params

    def __getitem__(self, item):
        return self._params[item]

    def __contains__(self, item):
        return item in self._params
