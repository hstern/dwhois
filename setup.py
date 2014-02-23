#!/usr/bin/env python

from distutils.core import setup

setup(name='dwhois',
        version='0.0',
        description='Distributed WHOIS Worker',
        author='Henry Stern',
        author_email='henry@stern.ca',
        packages=['dwhois']
        package_data={'dwhois': ['dwhois/default.conf']},
        scripts=['dwhois-worker'],
        )
