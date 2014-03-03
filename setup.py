#!/usr/bin/env python

from setuptools import setup

setup(name='dwhois',
        version='0.4',
        description='Distributed WHOIS',
        author='Henry Stern',
        author_email='henry@stern.ca',
        packages=['dwhois'],
        package_dir={'dwhois': 'src/dwhois'},
        package_data={'dwhois': ['default.conf']},
        scripts=['dwhois','dwhois-worker','dwhois-user'],
        install_requires=['requests >= 2.2.1', 'pymongo >= 2.6.3'],
        classifiers=[
            "Development Status :: 3 - Alpha",
            "Environment :: No Input/Output (Daemon)",
            "Intended Audience :: System Administrators",
            "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
            "Operating System :: POSIX :: Linux",
            "Topic :: Internet",
            "Topic :: Security",
            "Topic :: System :: Networking",
            ],
        )
