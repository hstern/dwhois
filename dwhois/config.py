#!/usr/bin/python

import ConfigParser
import os
import urlparse

config = ConfigParser.ConfigParser()
config.readfp(open(
    os.path.join(os.path.dirname(__file__), 'default.conf')))
config.read(['/etc/dwhois.conf',
    os.path.expanduser('~/.dwhois.conf'),
    './dwhois.conf'])

user=config.get('dwhois', 'user')
password=config.get('dwhois', 'password')

average_time = int(config.get('dwhois', 'average_time'))
api_base_url = config.get('dwhois', 'url')

request_url = urlparse.urljoin(api_base_url, 'request/')
upload_base_url = urlparse.urljoin(api_base_url, 'whois/')
