import subprocess
import tempfile

class WhoisError(Exception):
    pass

def whois(domain):
    buf = tempfile.TemporaryFile()
    errbuf = tempfile.TemporaryFile()

    try:
        subprocess.check_call(['whois', domain], stdout=buf, stderr=errbuf)
        buf.seek(0)
        return buf.read()
    except subprocess.CalledProcessError, e:
        errbuf.seek(0)
        raise WhoisError, errbuf.read()
