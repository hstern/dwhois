#!/usr/bin/env python

from setuptools import setup

setup(name='dwhois',
        version='0.2',
        description='Distributed WHOIS',
        author='Henry Stern',
        author_email='henry@stern.ca',
        packages=['dwhois'],
        package_dir={'dwhois': 'src/dwhois'},
        package_data={'dwhois': ['default.conf']},
        scripts=['dwhois','dwhois-worker','dwhois-user'],
        install_requires=['requests >= 2.2.1', 'pymongo >= 2.6.3'],
        )
