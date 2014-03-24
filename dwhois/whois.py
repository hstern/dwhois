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

def _load_config():
    return yaml.safe_load(pkg_resources.resource_string(__name__, 'whois.yml'))
whois_config = _load_config()

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

    #perform some input checking since
    #domain could come from an untrusted source
    domain=domain.strip()
    if not is_valid_object(domain):
        raise WhoisError, "invalid domain name: %s"%domain

    buf = tempfile.TemporaryFile()
    errbuf = tempfile.TemporaryFile()

    try:
        subprocess.check_call([whois_path, '--', domain], stdout=buf, stderr=errbuf)
        buf.seek(0)
        return buf.read()
    except subprocess.CalledProcessError:
        errbuf.seek(0)
        raise WhoisError, "whois failed: '%s'" % errbuf.read().rstrip()
