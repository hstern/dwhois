import requests
import sys
import urllib
import urlparse

from dwhois.config import api_base_url

class QueryError(Exception):
    pass

class DWhois:
    def __init__(self, base_url=api_base_url, user=None, password=None):
        self.base_url = urlparse.urljoin(base_url, 'whois/')
        self.base_user_url = urlparse.urljoin(base_url, 'user/')

        self.user = user
        self.password = password

    def get(self, domain):
        get_url = urlparse.urljoin(self.base_url, urllib.quote(domain, safe=''))

        try:
            r = requests.get(get_url,
                    auth=(self.user,self.password),
                    headers={ 'Accept' : '/application/json' },
                    stream=False,
                    verify=False)
            r.raise_for_status()

            return r.json()
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            raise WorkerError, e.message, sys.exc_traceback()

    def check(self, domain):
        get_url = urlparse.urljoin(self.base_url, urllib.quote(domain, safe=''))

        try:
            r = requests.head(get_url,
                    auth=(self.user,self.password),
                    headers={ 'Accept' : '/application/json' },
                    stream=False,
                    verify=False)

            if r.status_code == 200:
                return True
            elif r.status_code == 404:
                return False

            r.raise_for_status()

            raise WorkerError, 'Unexpected HTTP status code: %d'% r.status_code
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            raise WorkerError, e.message, sys.exc_traceback()

