import encodings
import re
import unittest

import dwhois.whois as dw
import IPy

_valid_label = re.compile(r'(?:[a-z0-9\-]+)', re.I)
_valid_domain = re.compile(r'^(?:{label}\.)*{label}$'.format(label=_valid_label.pattern), re.I)
_valid_handle = re.compile(r'^{label}-'.format(label=_valid_label.pattern), re.I)
_valid_tld = re.compile(r'^[-\.]{domain}'.format(domain=_valid_domain.pattern[1:-1]), re.I)

class TestWhois(unittest.TestCase):
    def test_whois_config(self):
        self.assertIsNotNone(dw.whois_config)
        self.assertIsInstance(dw.whois_config, dict)

    def test_whois_config_ripe_servers(self):
        self.assertIn('ripe_servers', dw.whois_config)
        self.assertIsInstance(dw.whois_config['ripe_servers'], list)
        for value in dw.whois_config['ripe_servers']:
            self.assertRegexpMatches(value, _valid_domain)

    def test_whois_config_hide_strings(self):
        self.assertIn('hide_strings', dw.whois_config)
        self.assertIsInstance(dw.whois_config['hide_strings'], list)
        for pair in dw.whois_config['hide_strings']:
            self.assertIsInstance(pair, list)
            self.assertEqual(len(pair), 2)
            for value in pair:
                self.assertIsInstance(value, bytes)

    def test_whois_config_nic_handles(self):
        self.assertIn('nic_handles', dw.whois_config)
        self.assertIsInstance(dw.whois_config['nic_handles'], dict)
        for key,value in dw.whois_config['nic_handles'].iteritems():
            self.assertRegexpMatches(key, _valid_handle)
            self.assertRegexpMatches(value, _valid_domain)

    def test_whois_config_ip_assign(self):
        self.assertIn('ip_assign', dw.whois_config)
        self.assertIsInstance(dw.whois_config['ip_assign'], dict)
        for key,value in dw.whois_config['ip_assign'].iteritems():
            self.assertEqual(IPy.IP(key).version(), 4)
            self.assertRegexpMatches(value, _valid_domain)

    def test_whois_config_ip6_assign(self):
        self.assertIn('ip6_assign', dw.whois_config)
        self.assertIsInstance(dw.whois_config['ip6_assign'], dict)
        for key,value in dw.whois_config['ip6_assign'].iteritems():
            self.assertEqual(IPy.IP(key).version(), 6)
            self.assertRegexpMatches(value, _valid_domain)

    def test_whois_config_as_del(self):
        self.assertIn('as_del', dw.whois_config)
        self.assertIsInstance(dw.whois_config['as_del'], list)
        for value in dw.whois_config['as_del']:
            self.assertIsInstance(value, dict)

            self.assertIn('first', value)
            self.assertGreaterEqual(value['first'], 0)
            self.assertLessEqual(value['first'], 65535)

            self.assertIn('last', value)
            self.assertGreaterEqual(value['last'], 0)
            self.assertLessEqual(value['last'], 65535)
            self.assertLessEqual(value['first'], value['last'])

            self.assertIn('serv', value)
            self.assertRegexpMatches(value['serv'], _valid_domain)

    def test_whois_config_as32_del(self):
        self.assertIn('as32_del', dw.whois_config)
        self.assertIsInstance(dw.whois_config['as32_del'], list)
        for value in dw.whois_config['as32_del']:
            self.assertIsInstance(value, dict)

            self.assertIn('first', value)
            self.assertGreaterEqual(value['first'], 0)
            self.assertLessEqual(value['first'], 4294967295)

            self.assertIn('last', value)
            self.assertGreaterEqual(value['last'], 0)
            self.assertLessEqual(value['last'], 4294967295)
            self.assertLessEqual(value['first'], value['last'])

            self.assertIn('serv', value)
            self.assertRegexpMatches(value['serv'], _valid_domain)

    def test_whois_config_tld_serv(self):
        self.assertIn('tld_serv', dw.whois_config)
        self.assertIsInstance(dw.whois_config['tld_serv'], dict)

        for key,value in dw.whois_config['tld_serv'].iteritems():
            self.assertRegexpMatches(key, _valid_tld)
            if value is not None:
                self.assertRegexpMatches(value, _valid_domain)

    def test_whois_config_servers_charset(self):
        self.assertIn('servers_charset', dw.whois_config)
        self.assertIsInstance(dw.whois_config['servers_charset'], dict)

        for key,value in dw.whois_config['servers_charset'].iteritems():
            self.assertRegexpMatches(key, _valid_domain)
            self.assertIsInstance(value, dict)
            self.assertIn('charset', value)
            encodings.codecs.getdecoder(value['charset'])
            self.assertIn('options', value)

    def test_extract_6to4(self):
        self.assertEquals(dw._extract_6to4('2002:c000:0204::/48'), '192.0.2.4')

    def test_extract_6to4_ipv4(self):
        self.assertRaises(dw.WhoisError, dw._extract_6to4, '192.168.0.1')

    def test_extract_6to4_not_6to4(self):
        self.assertRaises(dw.WhoisError, dw._extract_6to4, '2001::')

    def test_extract_6to4_invalid(self):
        self.assertRaises(ValueError, dw._extract_6to4, 'invalid address literal')

    def test_extract_teredo(self):
        self.assertEquals(dw._extract_teredo('2001:0:c000:0204::'), '192.0.2.4')

    def test_extract_teredo_ipv4(self):
        self.assertRaises(dw.WhoisError, dw._extract_teredo, '192.168.0.1')

    def test_extract_teredo_not_teredo(self):
        self.assertRaises(dw.WhoisError, dw._extract_teredo, '2002::')

    def test_extract_teredo_invalid(self):
        self.assertRaises(ValueError, dw._extract_teredo, 'invalid address literal')

    def test_normalize_domain(self):
        self.assertEquals(dw._normalize_domain('example.com'), 'example.com')
        self.assertEquals(dw._normalize_domain('Example.com'), 'example.com')
        self.assertEquals(dw._normalize_domain('example.com '), 'example.com')
        self.assertEquals(dw._normalize_domain(' example.com'), 'example.com')
        self.assertEquals(dw._normalize_domain('example.com.'), 'example.com')
        self.assertEquals(dw._normalize_domain('example.com..'), 'example.com')
        self.assertEquals(dw._normalize_domain('example.com.. \t'), 'example.com')
        self.assertEquals(dw._normalize_domain('test example.com.. \t'), 'example.com')

    def test_normalize_domain_idn(self):
        self.assertEquals(dw._normalize_domain(u'www.Alliancefran\xe7aise.nu'), 'www.xn--alliancefranaise-npb.nu')

    def test_server_for_ipv6(self):
        self.assertEquals(dw._guess_server('2001:0201::1'), 'whois.apnic.net')
        self.assertEquals(dw._guess_server('3ffe::1'), 'whois.6bone.net')

    def test_server_for_ipv6_teredo(self):
        self.assertEquals(dw._guess_server('2001:0:0808:0808::1'), 'whois.arin.net')

    def test_server_for_ipv6_6to4(self):
        self.assertEquals(dw._guess_server('2002:0808:0808::1'), 'whois.arin.net')

    def test_server_for_ipv6_unknown(self):
        self.assertRaises(dw.WhoisError, dw._guess_server, '::')

    def test_server_for_ipv4(self):
        self.assertEquals(dw._guess_server('8.8.8.8'), 'whois.arin.net')
        self.assertEquals(dw._guess_server('2.0.0.1'), 'whois.ripe.net')

    def test_server_for_ipv4_unknown(self):
        self.assertRaises(dw.WhoisError, dw._guess_server, '0.0.0.0')

    def test_server_for_email(self):
        self.assertRaises(dw.WhoisError, dw._guess_server, 'user@example.net')

    def test_server_for_asn(self):
        self.assertEquals(dw._guess_server('as1'), 'whois.arin.net')
        self.assertEquals(dw._guess_server('as306'), 'whois.nic.mil')
        self.assertEquals(dw._guess_server('as63488'), 'whois.apnic.net')
        self.assertEquals(dw._guess_server('as150000'), 'whois.apnic.net')
        self.assertEquals(dw._guess_server('as200000'), 'whois.ripe.net')

    def test_server_for_rspl(self):
        self.assertEquals(dw._guess_server('as'), 'whois.arin.net')
        self.assertEquals(dw._guess_server('astest'), 'whois.arin.net')

    def test_server_for_asn_invalid(self):
        self.assertRaises(dw.WhoisError, dw._guess_server, 'as0')
        self.assertRaises(dw.WhoisError, dw._guess_server, 'as2000000')
