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
"""
@var user: Username
@type user: string
"""
password=config.get('dwhois', 'password')
"""
@var password: Password
@type password: string
"""

average_time = config.getint('dwhois', 'average_time')
"""
@var average_time: Average processing+sleep time per domain in seconds
@type average_time: int
"""
api_base_url = config.get('dwhois', 'url')
"""
@var api_base_url: Base URL for API.  Trailing slash will be
automatically appended.
@type api_base_url: url
"""
if api_base_url[-1] != '/.':
    api_base_url += '/'

use_cache = config.getboolean('cache', 'use_cache')
"""
@var use_cache: Whether or not to use the MongoDB-backed cache.
@type use_cache: bool
"""
cache_url = config.get('cache', 'url')
"""
@var cache_url: URL to MongoDB.
@type cache_url: URL with mongodb schema
"""
cache_db = config.get('cache', 'db')
"""
@var cache_db: MongoDB database name.
@type cache_db: string
"""
cache_collection = config.get('cache', 'collection')
"""
@var cache_collection: MongoDB collection name.
@type cache_collection: string
"""
