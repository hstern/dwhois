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

import time
import unittest

import dwhois.timing as tm

class TestTiming(unittest.TestCase):
    @unittest.expectedFailure
    def test_rate_limit(self):
        start = time.time()
        iters = 20
        delay = 0.001
        tolerance=1.25
        for i in xrange(0,iters):
            with tm.RateLimiter(delay):
                pass
        self.assertGreater(time.time(), start+iters*delay)
        self.assertLess(time.time(), start+tolerance*iters*delay)

    @unittest.expectedFailure
    def test_random_rate_limiter(self):
        start = time.time()
        min = 0.001
        max = 0.005
        tolerance = 0.002
        with tm.RandomRateLimiter(min, max):
            pass
        self.assertGreater(time.time(), start+min)
        self.assertLess(time.time(), start+max+tolerance)

    # This is randomized and unbounded so we have to expect failures.
    @unittest.expectedFailure
    def test_gaussian_rate_limiter(self):
        start = time.time()
        mu = 0.001
        sigma = 0.001
        iters = 20

        mu_tolerance=1.1
        sigma_tolerance = 5

        for i in xrange(0,iters):
            with tm.GaussianRateLimiter(mu,sigma):
                pass

        self.assertGreater(time.time(), start+mu_tolerance*iters*mu-sigma_tolerance*sigma)
        self.assertLess(time.time(), start+mu_tolerance*iters*mu+sigma_tolerance*sigma)

    # This is randomized and unbounded so we have to expect failures.
    @unittest.expectedFailure
    def test_poisson_rate_limiter(self):
        start = time.time()
        average=0.001
        iters=20
        tolerance=1.5
        for i in xrange(0,iters):
            with tm.PoissonRateLimiter(average):
                pass

        self.assertGreater(time.time(), start+average*iters/tolerance)
        self.assertLess(time.time(), start+average*iters*tolerance)

    def test_exception_eating(self):
        with self.assertRaises(Exception):
            with tm.RateLimiter(sleep_time=0.0001):
                raise Exception
