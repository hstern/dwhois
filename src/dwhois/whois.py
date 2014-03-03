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

class WhoisError(Exception):
    """
    Raised when the WHOIS lookup fails.
    """

def whois(domain):
    """
    Retrieves a WHOIS record.

    @param domain: The domain to look up.
    @type domain: string

    @rtype: string

    @raise WhoisError: On lookup failure.
    """
    buf = tempfile.TemporaryFile()
    errbuf = tempfile.TemporaryFile()

    try:
        subprocess.check_call(['whois', domain], stdout=buf, stderr=errbuf)
        buf.seek(0)
        return buf.read()
    except subprocess.CalledProcessError:
        errbuf.seek(0)
        raise WhoisError, errbuf.read()
