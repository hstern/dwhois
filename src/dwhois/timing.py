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

"""
This package is used to rate limit anything.

Use it like this::

    with RateLimiter(sleep_time=1):
        do your action

It will sleep long enough so that the block takes at least the full
sleep time.

There are also randomized versions that follow the same use pattern.

Write your own by subclassing RateLimiter and overriding
RateLimiter.sleep_time.  There is no need to call super.__init__ but you
may if you want to.  Don't override __enter__ and __exit__.
"""

import random
import time

class RateLimiter:
    """
    Constant duration rate limiter.
    """
    def __init__(self, limit=1):
        """
        @param limit: How long each iteration should take.
        @type limit: float seconds
        """
        self.limit = limit

    def __enter__(self):
        self._t_start = time.time()
        return self

    def __exit__(self, type, value, traceback):
        """
        Sleeps for sleep_time - elapsed_time.
        """
        t_end = time.time()
        t_sleep = self.sleep_time() - (t_end - self._t_start)
        if t_sleep > 0:
            time.sleep(t_sleep)
        return False

    def sleep_time(self):
        """
        @return: How long this iteration should take.  Not how long to
        actually sleep.  That is based on the clock.
        @rval: float seconds
        """
        return self.limit

class RandomRateLimiter(RateLimiter):
    """
    Uniform random rate limiter.
    """
    def __init__(self, minval=0, maxval=1):
        """
        Sleep time is uniformly distributed over (minval,maxval).
        @type minval: float seconds
        @type maxval: float seconds

        @raise ValueError: If minval > maxval.
        """
        if maxval < minval:
            raise ValueError, 'Minval greater than maxval (%d > %d)' % (minval, maxval)
        self.minval = minval
        self.maxval = maxval

    def sleep_time(self):
        return self.minval + random.random() * (self.maxval - self.minval)

class GaussianRateLimiter(RateLimiter):
    """
    Gaussian random variate rate limiter.
    """
    def __init__(self, mu=1, sigma=1):
        """
        Sleep time is normally distributed about mu by sigma.

        @type mu: float seconds
        @type sigma: float seconds
        """
        self.mu = mu
        self.sigma = sigma

    def sleep_time(self):
        return max(0, random.gauss(self.mu, self.sigma))

class PoissonRateLimiter(RateLimiter):
    """
    Rate limiter designed to mimic a Poisson process.  This one looks
    the most like random traffic.
    """
    def __init__(self, average_time=1):
        """
        Sleep time is exponentially distributed about average_time.

        @type average_time: float seconds
        """
        self.average_time = average_time

    def sleep_time(self):
        return random.expovariate(1.0/self.average_time)
