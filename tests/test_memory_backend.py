import unittest
import random
from laurelin.server.memory_backend import MemoryBackend, LDAPObject
from laurelin.ldap.constants import Scope
from laurelin.ldap.filter import parse


class TestMemoryBackend(unittest.TestCase):
    def test_add_search(self):
        suffix = 'cn=test'
        mb = MemoryBackend(suffix)

        alpha0 = 'abcdefghijklmnopqrstuvwxyz'
        alpha1 = 'bcdefghijklmnopqrstuvwxyza'

        size = 3
        rdns = []
        for i in range(0, len(alpha0), size):
            attr = alpha0[i:i+size]
            val = alpha1[i:i+size]
            rdns.append(attr + '=' + val)

        with self.subTest('populate tree'):
            for rdn0 in rdns:
                mb.add(','.join((rdn0, suffix)))
                for rdn1 in rdns:
                    mb.add(','.join((rdn1, rdn0, suffix)))
                    for rdn2 in rdns:
                        mb.add(','.join((rdn2, rdn1, rdn0, suffix)))

        with self.subTest(dn=suffix):
            mb.search(suffix, Scope.BASE)
        for _ in range(10):
            rdn0 = random.choice(rdns)
            rdn1 = random.choice(rdns)
            rdn2 = random.choice(rdns)
            dn = ','.join((rdn2, rdn1, rdn0, suffix))
            with self.subTest(dn=dn):
                mb.search(dn, Scope.BASE)

        with self.subTest('subtree'):
            rdn0 = random.choice(rdns)
            dn = ','.join((rdn0, suffix))
            s = mb.search(dn, Scope.SUB)
            self.assertEqual(len(s), 91)

        with self.subTest('subtree level 2'):
            rdn0 = random.choice(rdns)
            rdn1 = random.choice(rdns)
            dn = ','.join((rdn1, rdn0, suffix))
            s = mb.search(dn, Scope.SUB)
            self.assertEqual(len(s), 10)

    def test_matches_filter(self):
        obj = LDAPObject('cn=test', {
            'foo': ['bar', 'baz'],
            'abc': ['def'],
            'ghi': ['jkl', 'mno']
        })

        pass_filters = [
            '(foo=bar)',
            '(&(foo=bar)(abc=def)(ghi=jkl))',
            '(|(ghi=mno)(doesnotexist=foo))',
            '(!(foo=nope))',
            'NOT (foo=nope) AND (abc=def) AND (ghi=mno)',
        ]
        for filter in pass_filters:
            with self.subTest('expected pass filter', filter=filter):
                self.assertTrue(obj.matches_filter(parse(filter)))

        fail_filters = [
            '(foo=nope)',
        ]
        for filter in fail_filters:
            with self.subTest('expected fail filter', filter=filter):
                self.assertFalse(obj.matches_filter(parse(filter)))
