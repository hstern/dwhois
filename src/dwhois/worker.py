import requests
import sys
import time
import urllib
import urlparse

from dwhois.config import api_base_url

class WorkerError(Exception):
    """
    Raised when an error occurs while talking to the remote server.
    """

class Worker:
    """
    Manages communications with the remote server.
    """
    def __init__(self, base_url=api_base_url, user=None, password=None,
            sleep_min=1, sleep_max=60):
        """
        @param base_url: base URL for the API
        @type base_url: url, must end with /
        @param user: username
        @type user: string
        @param password: password
        @type password: string
        @param sleep_min: Minimum sleep time on error.  Exponential backoff.
        @type sleep_min: float
        @param sleep_max: Maximum sleep time on error.
        @type sleep_max: float
        """
        self.base_url = api_base_url
        self.request_url = urlparse.urljoin(self.base_url, 'request/')
        self.upload_base_url = urlparse.urljoin(self.base_url, 'whois/')

        self.user = user
        self.password = password

        self.sleep_min = sleep_min
        self.sleep_max = sleep_max

    def queue(self, queue=None, number=None):
        """
        Inifitely returns domains needing processing.  Uses an exponential
        backoff algorithm upon communication errors.

        Warning: Iterator never raises StopIteration.
        Side-effect: Exceptions are printed to sys.stdout.

        @return: Iterator of domain names.
        @rtype: iter over strings
        """
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
                # TODO needs to be better
                print e.message

                time.sleep(error_sleep)
                error_sleep = min(self.error_sleep*2, self.sleep_max)

    def push_results(self, domain, text):
        """
        Uploads a WHOIS record to the server.

        @param domain: Domain name that was queried.
        @type domain: string
        @param text: WHOIS record.  Contains line breaks.
        @type text: string

        @raises WorkerError: On communication error.
        """

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
