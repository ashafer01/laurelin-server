import unittest

from laurelin.server.config import Config


class TestConfig(unittest.TestCase):
    def test_config(self):
        conf = Config({
            'a': {
                'b': {
                    'c': 'd',
                    'e': 'f',
                },
                'c': 'd',
                'e': {
                    'f': 'g',
                    'h': 'i',
                },
                'f': 'g',
            },
            'g': 'h',
            'i': 'j',
        })

        conf.load_dict({
            'a': {
                'e': {
                    'h': 'CHANGED'
                },
                'f': 'CHANGED',
            },
            'g': 'CHANGED',
        })

        self.assertEqual(conf['a']['b']['c'], 'd')
        self.assertEqual(conf['a']['b']['e'], 'f')
        self.assertEqual(conf['a']['c'], 'd')
        self.assertEqual(conf['a']['e']['f'], 'g')
        self.assertEqual(conf['a']['e']['h'], 'CHANGED')
        self.assertEqual(conf['a']['f'], 'CHANGED')
        self.assertEqual(conf['g'], 'CHANGED')
        self.assertEqual(conf['i'], 'j')
