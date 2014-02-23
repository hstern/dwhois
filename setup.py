#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='dwhois',
        version='0.0',
        description='Distributed WHOIS Worker',
        author='Henry Stern',
        author_email='henry@stern.ca',
        packages=find_packages(),
        package_data={'dwhois': ['dwhois/default.conf']},
        scripts=['dwhois-worker'],
        )
