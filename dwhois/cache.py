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

import copy

import bson
import pymongo

class Cache:
    """
    MongoDB-backed cache for WHOIS results to save on network traffic,
    credits, and server load.
    """

    def __init__(self, url='mongodb://localhost:27017/',
            db='dwhois', collection='dwhois'):
        """
        @type  url: url with mongodb schema
        @param url: MongoDB url
        @type  db: string
        @param db: MongoDB database name
        @type  collection: string
        @param collection: MongoDB collection name
        """

        self.client = pymongo.MongoClient(url)
        self.db = self.client[db]
        self.collection = self.db[collection]
        self.collection.ensure_index('domain_name')

    def add(self, v):
        """
        Adds a record to the cache.  Should be a dict and must have key
        domain_name.

        @type  v: dict
        @param v: Value to be added.
        """
        if 'domain_name' not in v:
            raise KeyError, 'domain'

        if 'whois' in v and type(v['whois']) == bytes:
            v = copy.deepcopy(v)
            v['whois'] = bson.binary.Binary(v['whois'])

        self.collection.insert(v)

    def get(self, domain, one=True):
        """
        Retrieves one or more records from the cache by domain name.
        Duplicates may occur if the server has told the worker to fetch
        a WHOIS record multiple times.

        @type  domain: string
        @param domain: Domain to be retrieved.
        @type  one: bool
        @param one: Retrieve only one record.

        @rtype: dict or list of dicts (one=False)
        @return: The record(s) requested.

        @raise KeyError: If they domain is not in the cache.
        """
        if one:
            rval = self.collection.find_one({'domain_name':domain})
            if rval:
                return rval
            raise KeyError, domain
        else:
            return self.collection.find({'domain_name':domain})

    def __contains__(self, domain):
        """
        @type  domain: str
        @param domain: Domain to be checked

        @rtype: bool
        @return: Whether or not the domain is in the cache.
        """
        return bool(self.collection.find_one({'domain_name':domain}))
