#!/usr/bin/env python

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

from setuptools import setup

setup(name='dwhois',
        version='0.8',
        description='Distributed WHOIS',
        author='Henry Stern',
        author_email='henry@stern.ca',
        packages=['dwhois'],
        package_dir={'dwhois': 'src/dwhois', 'tests': 'src/tests'},
        package_data={'dwhois': ['default.conf']},
        scripts=['dwhois','dwhois-worker','dwhois-user'],
        install_requires=['requests >= 2.2.1', 'pymongo >= 2.6.3'],
        classifiers=[
            'Development Status :: 3 - Alpha',
            'Environment :: No Input/Output (Daemon)',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
            'Operating System :: POSIX :: Linux',
            'Topic :: Internet',
            'Topic :: Security',
            'Topic :: System :: Networking',
            ],
        test_suite='tests',
        )
