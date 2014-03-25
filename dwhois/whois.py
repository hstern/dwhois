# dwhois - Distributed WHOIS
# Copyright (C) 2014  Henry Stern <henry@stern.ca>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import re
import socket
import struct
import subprocess
import tempfile

from dwhois.config import whois_path, whois_strict

import IPy
import pkg_resources
import yaml

whois_config = yaml.safe_load(pkg_resources.resource_string(__name__, 'whois.yml'))
_default_server = 'whois.arin.net'
_default_port = 43


class WhoisError(Exception):
    """
    Raised when the WHOIS lookup fails.
    """

def _normalize_domain(domain):
    """
    Normalizes a domain name by converting it to lower case, removing
    trailing dots and encoding with IDNA.  Like Marco d'Itri's whois,
    it assumes that the domain is the last space-separated token in
    the query.

    @param domain: A domain name.
    @type domain: unicode or bytes

    @rtype: bytes
    """
    domain = domain.split()[-1].lower()
    while domain[-1] == '.':
        domain = domain[:-1]
    return domain.encode('idna')

def _extract_teredo(addr):
    """
    Returns the IPv4 address embedded in a teredo address.

    @param addr: A valid teredo address literal.
    @type addr: string or IPy.IP
    @rtype: str

    @raise WhoisError: If the address literal is not a teredo.
    @raise ValueError: If the address literal is invalid.
    """
    addr = IPy.IP(addr)
    if addr.iptype() != 'TEREDO':
        raise WhoisError('Address \'{0}\' is not 6to4'.format(addr))
    return socket.inet_ntoa(struct.pack('!I', addr.int() >> 64 & 0x0FFFFFFFF))


def _extract_6to4(addr):
    """
    Returns the IPv4 address embedded in a 6to4 address.

    @param addr: A valid 6to4 address literal.
    @type addr: string or IPy.IP
    @rtype: str

    @raise WhoisError: If the address literal is not a 6to4.
    @raise ValueError: If the address literal is invalid.
    """
    addr = IPy.IP(addr)
    if addr.iptype() != '6TO4':
        raise WhoisError('Address \'{0}\' is not 6to4'.format(addr))
    return socket.inet_ntoa(struct.pack('!I', addr.int() >> 80 & 0x0FFFFFFFF))

_ip6_type_handlers = {
        'TEREDO' : _extract_teredo,
        '6TO4' : _extract_6to4,
        }

def _guess_server(query):
    try:
        ip = IPy.IP(query)

        if ip.version() == 6:
            if ip.iptype() in _ip6_type_handlers:
                return _guess_server(_ip6_type_handlers[ip.iptype()](ip))
            else:
                if ip in IPy.IP('::/16'):
                    raise WhoisError, 'Unknown whois server for ::/16'
                for cidr,server in whois_config['ip6_assign'].iteritems():
                    net = IPy.IP(cidr)
                    if ip in net:
                        return server
                return _default_server
        else:
            if ip in IPy.IP('0.0.0.0/8'):
                raise WhoisError, 'Unknown whois server for 0.0.0.0/8'

            for cidr,server in whois_config['ip_assign'].iteritems():
                net = IPy.IP(cidr)
                if ip in net:
                    return server
            return _default_server
    except ValueError:
        pass

    if query.startswith('as'):
        m = re.match(r'^as([0-9]+)', query, re.I)

        if m:
            as_num = int(m.group(1))

            if as_num < 65536:
                for as_assign in whois_config['as_del']:
                    if as_num >= as_assign['first'] and as_num <= as_assign['last']:
                        return as_assign['serv']
            else:
                for as_assign in whois_config['as32_del']:
                    if as_num >= as_assign['first'] and as_num <= as_assign['last']:
                        return as_assign['serv']
            raise WhoisError, 'Unknown AS number.'
        else:
            return _default_server

    if '@' in query:
        raise WhoisError, "No whois server is known for email addresses."

    # NSI NIC handle
    if not re.search(r'[\.\-]', query):
        if query.startswith('!'):
            return 'whois.networksolutions.com'
        else:
            raise WhoisError, 'Unknown NIC handle type'

    for handle,server in whois_config['nic_handles'].iteritems():
        if query.startswith(handle):
            return server

    raise WhoisError, 'Unknown query type'

def is_valid_object(candidate):
    """
    Returns True if candidate is a valid WHOIS object.  If the whois.strict
    option is set then this means that it is only alphanumerics, dashes,
    underscores, and at symbols, separated by whitespace, otherwise this
    returns True for every string as the WHOIS protocol supports binary
    data.

    @param candidate: The input string to check
    @type candidate: string

    @rtype: boolean
    """
    if whois_strict:
        return re.match(r'^[a-z0-9\-_\.@]+$', candidate, re.I) is not None
    return True

def whois(domain):
    """
    Retrieves a WHOIS record.

    @param domain: The domain to look up.
    @type domain: string

    @rtype: string

    @raise WhoisError: On lookup failure.
    """
    return ExternalWhoisClient().lookup(domain)

class WhoisClient:
    def lookup(self, query):
        """
        Retrieves a WHOIS record.

        @param query: The query to look up.
        @type query: string

        @rtype: string

        @raise WhoisError: On lookup failure.
        """
        raise NotImplementedError

class ExternalWhoisClient(WhoisClient):
    """
    A WHOIS client that uses an external program to resolve queries.
    It must handle arguments of the form "-- domain".  It is expected
    that most people will use Marco d'Itri's WHOIS client.
    """
    def __init__(self, path=whois_path):
        """
        @param path: Path to the whois binary.
        @type path: string
        """
        self.path = whois_path

    def lookup(self, query):
        """
        Retrieves a WHOIS record.

        @param query: The query to look up.
        @type query: string

        @rtype: string

        @raise WhoisError: On lookup failure.
        """
        #perform some input checking since
        #domain could come from an untrusted source
        query=query.strip()
        if not is_valid_object(query):
            raise WhoisError, "invalid query name: %s"%query

        buf = tempfile.TemporaryFile()
        errbuf = tempfile.TemporaryFile()

        try:
            subprocess.check_call([self.path, '--', query], stdout=buf, stderr=errbuf)
            buf.seek(0)
            return buf.read()
        except subprocess.CalledProcessError:
            errbuf.seek(0)
            raise WhoisError, "whois failed: '%s'" % errbuf.read().rstrip()
