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

import requests
import sys
import urllib
import urlparse

from dwhois.config import api_base_url

class QueryError(Exception):
    """
    Raised when an error occurs while talking to the remote server.
    """

class DWhois:
    """
    Manages communications with the remote server.
    """
    def __init__(self, base_url=api_base_url, user=None, password=None):
        """
        @param base_url: base URL for the API
        @type base_url: url, must end with /
        @param user: username
        @type user: string
        @param password: password
        @type password: string
        """
        self.base_url = urlparse.urljoin(base_url, 'whois/')
        self.base_user_url = urlparse.urljoin(base_url, 'user/')
        self.request_url = urlparse.urljoin(base_url, 'request/')

        self.user = user
        self.password = password

    def get(self, domain):
        """
        Retrieves JSON-packed WHOIS data from the remote server.

        @param domain: The domain to retrieve.
        @param type: string

        @return: WHOIS data plus domain name and submit time.
        @rtype: decoded JSON dict

        @raise QueryError: On communications or authentication failure.
        """
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
        """
        Checks whether or not the remote server has WHOIS data for
        domain.

        @param domain: The domain to check.
        @param type: string

        @rtype: bool

        @raise QueryError: On communications or authentication failure.
        """
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
        """
        Submits a list of domains for processing by workers.

        @param domains: The domains to submit.
        @param type: iterable of strings

        @raise QueryError: On communications or authentication failure.
        """
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
        """
        Retrieves information about a user's account.

        @param user: username
        @type  user: string

        @return: Decoded JSON dict
        @rtype: dict

        @raise QueryError: On communications or authentication failure.
        """
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

