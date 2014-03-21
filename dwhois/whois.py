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

import subprocess
import tempfile
import re

from dwhois.config import whois_path, whois_strict

class WhoisError(Exception):
    """
    Raised when the WHOIS lookup fails.
    """

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
