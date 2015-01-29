#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, \
    with_statement  # use the features of python 3

import collections
import logging
import time


# this LRUCache is optimized for concurrency, not QPS
# n: concurrency, keys stored in the cache
# m: visits not timed out, proportional to QPS * timeout
# get & set is O(1), not O(n). thus we can support very large n
# TODO: if timeout or QPS is too large, then this cache is not very efficient,
# as sweep() causes long pause


class LRUCache(collections.MutableMapping):                 # ABCs for read-only and mutable mappings.
    """This class is not thread safe"""

    def __init__(self, timeout=60, close_callback=None, *args, **kwargs):
        self.timeout = timeout                              # the cache expire time
        self.close_callback = close_callback                # called when value will be swept from cache
        self._store = {}                                    # dict<key, value>: store cache data key value
        self._time_to_keys = collections.defaultdict(list)  # defaultdict<time, list<key>>
        # defaultdict: dict subclass that calls a factory function to supply missing values
        self._keys_to_last_time = {}                        # dict<key, time> stores the last time of one key visited.
        self._last_visits = collections.deque()             # deque<time> store all the time once key is visited.
        self.update(dict(*args, **kwargs))                  # use the free update to set keys

    def __getitem__(self, key):
        # O(1)
        t = time.time()
        self._keys_to_last_time[key] = t
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)
        return self._store[key]

    def __setitem__(self, key, value):
        # O(1)
        t = time.time()
        self._keys_to_last_time[key] = t
        self._store[key] = value
        self._time_to_keys[t].append(key)
        self._last_visits.append(t)

    def __delitem__(self, key):
        # O(1)
        del self._store[key]
        del self._keys_to_last_time[key]

    def __iter__(self):
        return iter(self._store)

    def __len__(self):
        return len(self._store)

    def sweep(self):
        # O(m)
        now = time.time()
        c = 0                                           # use to log how many keys has been swept.
        while len(self._last_visits) > 0:
            least = self._last_visits[0]                # fetch the oldest time point
            if now - least <= self.timeout:             # the oldest time point hasn't expire
                break
            if self.close_callback is not None:         # callback function has been set
                for key in self._time_to_keys[least]:   # fetch each key visited on the oldest time
                    if key in self._store:              # finded the cache key
                        if now - self._keys_to_last_time[key] > self.timeout:
                            value = self._store[key]    # get the key of the last time and check expire or yet.
                            self.close_callback(value)  # call callback
            for key in self._time_to_keys[least]:
                self._last_visits.popleft()             # can't understand and have error personally
                                                        # @Sunny: use popleft to remove oldest time point in last visits
                if key in self._store:
                    if now - self._keys_to_last_time[key] > self.timeout:
                        del self._store[key]
                        del self._keys_to_last_time[key]
                        c += 1
            del self._time_to_keys[least]
        if c:
            logging.debug('%d keys swept' % c)


def test():
    c = LRUCache(timeout=0.3)

    c['a'] = 1
    assert c['a'] == 1

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c

    c['a'] = 2
    c['b'] = 3
    time.sleep(0.2)
    c.sweep()
    assert c['a'] == 2
    assert c['b'] == 3

    time.sleep(0.2)
    c.sweep()
    c['b']
    time.sleep(0.2)
    c.sweep()
    assert 'a' not in c
    assert c['b'] == 3

    time.sleep(0.5)
    c.sweep()
    assert 'a' not in c
    assert 'b' not in c


if __name__ == '__main__':
    test()
