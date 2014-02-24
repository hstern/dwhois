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
