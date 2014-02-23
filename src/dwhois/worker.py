import requests
import sys
import time
import urllib
import urlparse

from dwhois.config import api_base_url

class WorkerError(Exception):
    pass

class Worker:
    def __init__(self, base_url=api_base_url, user=None, password=None, sleep_min=1, sleep_max=60):
        self.base_url = api_base_url
        self.request_url = urlparse.urljoin(self.base_url, 'request/')
        self.upload_base_url = urlparse.urljoin(self.base_url, 'whois/')

        self.user = user
        self.password = password

        self.sleep_min = sleep_min
        self.sleep_max = sleep_max

    def queue(self, queue=None, number=None):
        request_url = self.request_url
        if queue:
            if request_url[-1] != '/':
                request_url += '/'
            request_url = urlparse.urljoin(request_url, queue)
        if number:
            if request_url[-1] != '/':
                request_url += '/'
            request_url = urlparse.urljoin(request_url, str(number))

        error_sleep = self.sleep_min
        while True:
            try:
                r = requests.get(request_url,
                        auth=(self.user,self.password),
                        stream=False,
                        verify=False)
                r.raise_for_status()

                error_sleep = self.sleep_min
                for domain in r.text.split():
                    yield domain
            except (requests.exceptions.HTTPError,
                    requests.exceptions.ConnectionError), e:
                print e.message

                time.sleep(error_sleep)
                error_sleep = min(self.error_sleep*2, self.sleep_max)

    def push_results(self, domain, text):
        upload_url = urlparse.urljoin(self.upload_base_url, urllib.quote(domain, safe=''))

        try:
            r = requests.put(upload_url,
                auth=(self.user,self.password),
                data = text,
                stream=False,
                verify=False)
            r.raise_for_status()
        except (requests.exceptions.HTTPError,
                requests.exceptions.ConnectionError), e:
            raise WorkerError, e.message, sys.exc_traceback
