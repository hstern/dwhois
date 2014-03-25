#!/usr/bin/env python

import argparse
import os
import sys

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('query')
    args = parser.parse_args()

    sys.stdout.write(open(os.path.join(os.path.dirname(__file__), 'whois_data', args.query)).read())
