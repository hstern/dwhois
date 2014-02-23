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
        self.request_url = urlparse.urljoin(base_url, 'request/')

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
            raise QueryError, e.message, sys.exc_traceback

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

            raise QueryError, 'Unexpected HTTP status code: %d'% r.status_code
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            raise QueryError, e.message, sys.exc_traceback

    def submit(self, domains, queue=None):
        request_url = self.request_url
        if queue:
            if request_url[-1] != '/':
                request_url += '/'
            request_url = urlparse.urljoin(request_url, queue)

        try:
            r = requests.post(request_url,
                    data='\n'.join(domains),
                    auth=(self.user,self.password),
                    headers={ 'Accept' : '/application/json' },
                    stream=False,
                    verify=False)
            r.raise_for_status()
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            raise QueryError, e.message, sys.exc_traceback


    def get_user(self, user):
        user_url = urlparse.urljoin(self.base_user_url, urllib.quote(user, safe=''))

        try:
            r = requests.get(user_url,
                    auth=(self.user,self.password),
                    headers={ 'Accept' : '/application/json' },
                    stream=False,
                    verify=False)
            r.raise_for_status()

            return r.json()
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            raise QueryError, e.message, sys.exc_traceback

