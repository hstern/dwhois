#!/usr/bin/python

import ConfigParser
import os

config = ConfigParser.ConfigParser()
config.readfp(open(
    os.path.join(os.path.dirname(__file__), 'default.conf')))
config.read(['/etc/dwhois.conf',
    os.path.expanduser('~/.dwhois.conf'),
    './dwhois.conf'])

user=config.get('dwhois', 'user')
password=config.get('dwhois', 'password')

average_time = config.getint('dwhois', 'average_time')
api_base_url = config.get('dwhois', 'url')

use_cache = config.getboolean('cache', 'use_cache')
cache_url = config.get('cache', 'url')
cache_db = config.get('cache', 'db')
cache_collection = config.get('cache', 'collection')
