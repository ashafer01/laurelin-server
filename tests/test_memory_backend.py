import asyncio
import random
import unittest

from laurelin.ldap import rfc4511
from laurelin.ldap.constants import Scope
from laurelin.ldap.filter import parse

from laurelin.server.memory_backend import MemoryBackend, LDAPObject


def make_search_request(base_dn, scope, filter=None, limit=None):
    req = rfc4511.SearchRequest()
    req.setComponentByName('baseObject', rfc4511.LDAPDN(base_dn))
    req.setComponentByName('scope', scope)
    if filter:
        req.setComponentByName('filter', parse(filter))
    if limit is not None:
        req.setComponentByName('sizeLimit', rfc4511.Integer0ToMax(limit))
    return req


def make_add_request(dn, attrs=None):
    req = rfc4511.AddRequest()
    req.setComponentByName('entry', rfc4511.LDAPDN(dn))
    al = rfc4511.AttributeList()
    if attrs:
        i = 0
        for attr_type, attr_vals in attrs.items():
            attr = rfc4511.Attribute()
            attr.setComponentByName('type', rfc4511.AttributeDescription(attr_type))
            vals = rfc4511.Vals()
            j = 0
            for val in attr_vals:
                vals.setComponentByPosition(j, rfc4511.AttributeValue(val))
                j += 1
            attr.setComponentByName('vals', vals)
            al.setComponentByPosition(i, attr)
            i += 1
    req.setComponentByName('attributes', al)
    return req


async def asynclist(awaitable):
    ret = []
    async for i in awaitable:
        ret.append(i)
    return ret


class TestMemoryBackend(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(None)

    def test_add_search(self):
        async def run_test():
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
                    mb.add(make_add_request(','.join((rdn0, suffix))))
                    for rdn1 in rdns:
                        mb.add(make_add_request(','.join((rdn1, rdn0, suffix))))
                        for rdn2 in rdns:
                            mb.add(make_add_request(','.join((rdn2, rdn1, rdn0, suffix))))

            with self.subTest(dn=suffix):
                await asynclist(mb.search(make_search_request(suffix, Scope.BASE)))
            for _ in range(10):
                rdn0 = random.choice(rdns)
                rdn1 = random.choice(rdns)
                rdn2 = random.choice(rdns)
                dn = ','.join((rdn2, rdn1, rdn0, suffix))
                with self.subTest(dn=dn):
                    await asynclist(mb.search(make_search_request(dn, Scope.BASE)))

            with self.subTest('subtree'):
                rdn0 = random.choice(rdns)
                dn = ','.join((rdn0, suffix))
                s = await asynclist(mb.search(make_search_request(dn, Scope.SUB)))
                self.assertEqual(len(s), 91)

            with self.subTest('subtree with limit'):
                limit = 17
                rdn0 = random.choice(rdns)
                dn = ','.join((rdn0, suffix))
                s = await asynclist(mb.search(make_search_request(dn, Scope.SUB, limit=limit)))
                self.assertEqual(len(s), limit)

            with self.subTest('subtree level 2'):
                rdn0 = random.choice(rdns)
                rdn1 = random.choice(rdns)
                dn = ','.join((rdn1, rdn0, suffix))
                s = await asynclist(mb.search(make_search_request(dn, Scope.SUB)))
                self.assertEqual(len(s), 10)

        self.loop.run_until_complete(run_test())

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
            '(foo=*)',
            '(!(nope=*))',
            '(foo=*ar)',
            '(foo=ba*)',
            '(foo=*a*)',
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
