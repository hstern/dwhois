#!/usr/bin/env python

from setuptools import setup

setup(name='dwhois',
        version='0.1',
        description='Distributed WHOIS',
        author='Henry Stern',
        author_email='henry@stern.ca',
        packages=['dwhois'],
        package_dir={'dwhois': 'src/dwhois'},
        package_data={'dwhois': ['default.conf']},
        scripts=['dwhois','dwhois-worker'],
        )
