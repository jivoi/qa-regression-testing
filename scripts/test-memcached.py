#!/usr/bin/python
#
#    test-memcached.py quality assurance test script for memcached
#    Copyright (C) 2014 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: memcached libmemcached-tools
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-<script>.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-<script>.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-<script>.tar.gz
    # cd /tmp/qrt-test-<script> ; ./install-packages ./test-<script>.py
    # ./test-<script>.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import os
import subprocess
import sys
import unittest
import testlib
import socket

try:
    from private.qrt.memcached import PrivateMemcachedTest
except ImportError:
    class PrivateMemcachedTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class MemcachedTest(testlib.TestlibCase, PrivateMemcachedTest):
    '''Test memcached.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.daemon = testlib.TestDaemon("/etc/init.d/memcached")
        self.daemon.restart()

        # Add some data
        self.test_data = { 'colour': 'blue',
                           'size'  : 'xl',
                           'day'   : 'friday',
                           'month' : 'january' }

        for k in self.test_data:
            self._set_key(k, self.test_data[k])

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _send_cmd(self, request="", content="", invert = False, limit=4096):
        '''Sends a command to memcached'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 11211))
        s.send(request)
        data = s.recv(4096)
        s.close()

        if content != "":
            self._word_find(data, content, invert = invert)

        return data

    def _set_key(self, key, value, ignore=False):
        '''Sets a key'''
        command = "set %s 0 0 %s\r\n%s\r\n" % (key, len(value), value)
        result = self._send_cmd(command)
        if ignore == False:
            self.assertEqual(result.splitlines()[0], "STORED", "Couldn't fine STORED response!")
        return result

    def _add_key(self, key, value, ignore=False):
        '''Adds a key'''
        command = "add %s 0 0 %s\r\n%s\r\n" % (key, len(value), value)
        result = self._send_cmd(command)
        if ignore == False:
            self.assertEqual(result.splitlines()[0], "STORED", "Couldn't fine STORED response!")
        return result

    def _get_key(self, key):
        '''Gets a key'''
        command = "get %s\r\n" % key
        result = self._send_cmd(command)
        first = result.splitlines()[0]
        self.assertFalse("ERROR" in first, "Found ERROR in result!")
        first_split = first.split(" ")

        # See if there are no results
        if first_split[0] == "END":
            return None

        value = result.splitlines()[1]

        self.assertEqual(first_split[0], "VALUE", "Couldn't find VALUE response!")
        self.assertEqual(first_split[1], key, "Couldn't find key!")
        self.assertEqual(first_split[3], "%s" % len(value), "Value length doesn't match!")
        self.assertEqual(result.splitlines()[2], "END", "Couldn't fine END response!")
        return value

    def test_sample_data(self):
        '''Test sample data'''
        for k in self.test_data:
            error = "Could not find key %s!" % k
            self.assertEqual(self._get_key(k), self.test_data[k], error)

    def test_add(self):
        '''Test adding data'''

        new_key = "gem"
        new_value = "diamond"

        # See if we can add a new key
        self._add_key(new_key, new_value)
        self.assertEqual(self._get_key(new_key), new_value,
                         "Could not find key!")

        # Try adding an existing key (should fail)
        self.assertTrue(self._get_key("colour") == "blue",
                         "Colour should be blue!")

        response = self._add_key("colour", "purple", ignore=True)
        self.assertTrue("NOT_STORED" in response,
                        "Didn't find NOT_STORED in %s!" % response)

        self.assertFalse(self._get_key("colour") == "purple",
                         "Colour should not be purple!")

        self.assertTrue(self._get_key("colour") == "blue",
                         "Colour should be blue!")

    def test_set(self):
        '''Test setting data'''

        new_key = "gem"
        new_value = "diamond"

        # See if we can set a new key
        self._set_key(new_key, new_value)
        self.assertEqual(self._get_key(new_key), new_value,
                         "Could not find key!")

        # Try setting an existing key (should work)
        self.assertTrue(self._get_key("colour") == "blue",
                         "Colour should be blue!")

        self._set_key("colour", "purple")
        self.assertTrue(self._get_key("colour") == "purple",
                         "Colour should be purple!")

    def test_memcstat(self):
        '''Test memcstat'''
        search = "Server: localhost (11211)"
        self.assertShellOutputContains(search, ['memcstat', '--servers=localhost'], expected=0)

    def test_memccapable(self):
        '''Test memccapable'''
        search = "[pass]"
        self.assertShellOutputContains(search, ['memccapable'])

    def test_memccat(self):
        '''Test memccat'''
        search = "blue"
        self.assertShellOutputContains(search, ['memccat', '--servers=localhost', 'colour'], expected=0)

    def test_memcrm(self):
        '''Test memcrm'''

        self.assertTrue(self._get_key("colour") == "blue",
                         "Colour should be blue!")

        self.assertShellExitEquals(0, ['memcrm', '--servers=localhost', 'colour'])

        self.assertTrue(self._get_key("colour") == None,
                         "Colour key still exists!")

    def test_memcdump(self):
        '''Test memcdump'''

        rc, result = self.shell_cmd(['memcdump', '--servers=localhost'])

        for k in self.test_data:
            error = "Could not find key '%s' in result '%s'!" % (k, result)
            self.assertTrue(k in result, error)

    def test_cve_2011_4971(self):
        '''Test CVE-2011-4971'''

        self.assertTrue(self._get_key("colour") == "blue",
                         "Colour should be blue!")

        # https://code.google.com/p/memcached/issues/detail?id=192
        bad_cmd = '\x80\x12\x00\x01\x08\x00\x00\x00\xff\xff\xff\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

        self._send_cmd(bad_cmd)

        # See if it is still responding
        self.assertTrue(self._get_key("colour") == "blue",
                         "Colour should be blue!")

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
