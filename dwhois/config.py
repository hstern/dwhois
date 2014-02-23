#!/usr/bin/python

import ConfigParser
import os
import urlparse

config = ConfigParser.ConfigParser()
config.readfp(open(
    os.path.join(os.path.dirname(__file__), 'default.conf')))
config.read(['/etc/whois-worker.conf',
    os.path.expanduser('~/.whois-worker.conf'),
    './whois-worker.conf'])

user=config.get('whois-worker', 'user')
password=config.get('whois-worker', 'password')

average_time = int(config.get('whois-worker', 'average_time'))
api_base_url = config.get('whois-worker', 'url')

request_url = urlparse.urljoin(api_base_url, 'request/')
upload_base_url = urlparse.urljoin(api_base_url, 'whois/')
