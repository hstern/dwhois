import random
import time

class RateLimiter:
    def __init__(self, sleep_time=1):
        self.sleep_time = sleep_time

    def __enter__(self):
        self._t_start = time.time()
        return self

    def __exit__(self, type, value, traceback):
        t_end = time.time()
        t_sleep = self.sleep_time() - (t_end - self._t_start)
        if t_sleep > 0:
            # TODO logger
            print 'Sleeping %f' % t_sleep
            time.sleep(t_sleep)
        return True

    def sleep_time(self):
        return self.sleep_time

class RandomRateLimiter(RateLimiter):
    def __init__(self, minval=0, maxval=1):
        if maxval < minval:
            raise ValueError, 'Minval greater than maxval (%d > %d)' % (minval, maxval)
        self.minval = minval
        self.maxval = maxval

    def sleep_time(self):
        return self.minval + random.random() * (self.maxval - self.minval)

class GaussianRateLimiter(RateLimiter):
    def __init__(self, mu=1, sigma=1):
        self.mu = mu
        self.sigma = sigma

    def sleep_time(self):
        return max(0, random.gauss(self.mu, self.sigma))

class PoissonRateLimiter(RateLimiter):
    def __init__(self, average_time=1):
        self.average_time = average_time

    def sleep_time(self):
        return random.expovariate(1.0/self.average_time)
