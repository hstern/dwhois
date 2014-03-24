import unittest

import dwhois.whois as dw

class TestWhois(unittest.TestCase):
    def test_extract_6to4(self):
        self.assertEquals(dw._extract_6to4('2002:c000:0204::/48'), '192.0.2.4')

    def test_extract_6to4_ipv4(self):
        self.assertRaises(dw.WhoisError, dw._extract_6to4, '192.168.0.1')

    def test_extract_6to4_not_6to4(self):
        self.assertRaises(dw.WhoisError, dw._extract_6to4, '2001::')

    def test_extract_6to4_invalid(self):
        self.assertRaises(ValueError, dw._extract_6to4, 'invalid address literal')
