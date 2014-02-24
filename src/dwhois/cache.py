import pymongo

class Cache:
    def __init__(self, url='mongodb://localhost:27017/',
            db='dwhois', collection='dwhois'):
        self.client = pymongo.MongoClient(url)
        self.db = self.client[db]
        self.collection = self.db[collection]

    def add(self, v):
        if 'domain_name' not in v:
            raise KeyError, 'domain'
        self.collection.insert(v)

    def get(self, domain, one=True):
        if one:
            rval = self.collection.find_one({'domain_name':domain})
            if rval:
                return rval
            raise KeyError, domain
        else:
            return self.collection.find({'domain_name':domain})

    def __contains__(self, domain):
        return bool(self.collection.find_one({'domain_name':domain}))
