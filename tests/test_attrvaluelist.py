import unittest

from laurelin.server.schema import get_schema
from laurelin.server.memory_backend.attrvaluelist import AttrValueList


class TestAttrValueList(unittest.TestCase):
    def __init__(self, *args, **kwds):
        unittest.TestCase.__init__(self, *args, **kwds)
        schema = get_schema()
        schema.load_builtin()
        schema.resolve()

    def test_equals(self):
        avl = AttrValueList('testingFakeAttribute')
        val1 = 'val1'
        val2 = 'val2'
        val3 = 'val3'
        avl.append(val1)
        avl.append(val2)
        avl.append(val3)
        self.assertTrue(avl.equals(val1))
        self.assertTrue(avl.equals(val2))
        self.assertTrue(avl.equals(val3))
        self.assertFalse(avl.equals('abc'))
        self.assertFalse(avl.equals('def'))
