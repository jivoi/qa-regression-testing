#!/usr/bin/python
#
#    test-software-properties.py quality assurance test script for software-properties
#    Copyright (C) 2012 Canonical Ltd.
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
# QRT-Packages: python-software-properties
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
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'

    TODO:
    - test more than apt-add-repository
'''


import unittest, sys
import testlib
import threading
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

try:
    from private.qrt.SoftwareProperties import PrivateSoftwarePropertiesTest
except ImportError:
    class PrivateSoftwarePropertiesTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class WebServer(HTTPServer):
    '''HTTPServer class with extra parameters.'''
    data = ''

class WebServerHandler(BaseHTTPRequestHandler):
    '''A simple web server to test apt-add-repository.'''
    def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

    def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.server.data)

class SoftwarePropertiesTest(testlib.TestlibCase, PrivateSoftwarePropertiesTest):
    '''Test software-properties.'''
    server = None
    server_thread = None

    def setUp(self):
        '''Set up prior to each test_* function'''

        self.ppa = 'ppa:mdeslaur'
        self.ppa_fp = '1E16BFA90DD9C36A4163BFAA8CA686453D4DECBC'
        self.ppa_id = self.ppa_fp[-8:]
        self.ppa_key = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.0.10

mI0ESXhICwEEAMiiL8aMIwQj076m4eWwvHr6vtyo7xAf1KLCxTcBefhbYvSeFg9v8wnMMW0H
0fGFAFn9KW7JlJF2qK3BqBE0C1FiJnUbk33qN0UZtQlNziEW7//8eEZUhucRgt/whbV2fVp8
D0QqLyeBPZpAo11qNjlpc+95iSswFpdczmHp9pj3ABEBAAG0IkxhdW5jaHBhZCBQUEEgZm9y
IE1hcmMgRGVzbGF1cmllcnOItgQTAQIAIAUCSXhICwIbAwYLCQgHAwIEFQIIAwQWAgMBAh4B
AheAAAoJEIymhkU9Tey8vDMEAIrHCoa2FWIJ08J/U9Akh4aLWriK4m6rNrAJjLUDTdU4x24q
4Y1dFOj+QcEYRDySlObbGYN66qEzaclAPn7uAZ9KMTW+g1Dl251SKKaGL5DzCo2eA1DpTBLJ
412qnORKQBv9KKs8Ygu5GWJN6yZxEa6t4cUkZbdIFriKDHehlE42
=CbvY
-----END PGP PUBLIC KEY BLOCK-----
'''

        self.wrong_ppa_fp = 'D74BCDB869347B100A7286DB1089FEE9BA4C5BFF'
        self.wrong_ppa_key = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: SKS 1.0.10

mI0ESXZlMAEEALY/dXNXK4q+YflZdrFh2PIHv632swyoegieFbciPZU4yK76f5D+3m6Oedxv
nZJjLCedyDD7/q+CCakHEoqyO3U5NFUyxqXTHn91cmMqqUbTZjBxpPGRwd2stPQDQZM49yHE
E2b4cn0b4iCmrqGR95rVnfjRkNvzHGpswg47BSjHABEBAAG0IkxhdW5jaHBhZCBQUEEgZm9y
IEphbWllIFN0cmFuZGJvZ2WItgQTAQIAIAUCSXZlMAIbAwYLCQgHAwIEFQIIAwQWAgMBAh4B
AheAAAoJEBCJ/um6TFv/VkMEAKIuwMipO91autpX8MIqRGw/3io2KbsSm7au9JYuhCm6VlHj
3ObfrxnWR2Rz8XSrpbW0UMFTgZLom9GbgpLyEFVRhmIOF5s4gTCrGTGlKxZqVN8bH+DOMy/E
/XoK68Vj9KD5M+4g2hpqX+sgl0/fi7BVD2SKD2g45ORZcywZV55F
=Kast
-----END PGP PUBLIC KEY BLOCK-----
'''

        self.trusted = "/etc/apt/trusted.gpg"
        testlib.config_replace(self.trusted, "", True)

        self.port = 5080
        self.keyserver = "http://127.0.0.1:%s" % self.port

        self.hosts = "/etc/hosts"
        if self.lsb_release['Release'] < 11.10:
            testlib.config_replace(self.hosts, "", True)
            self.port = 11371

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib.config_restore(self.trusted)
        if self.lsb_release['Release'] < 11.10:
            testlib.config_restore(self.hosts)

        if self.server != None:
            self.server.server_close()
            self.server = None

    def _call_aar(self, repo, string, keyserver=None, expected_rc = 0, invert_match = False):
        '''Call apt-add-repository and check for a specific string in output'''

        command = ['apt-add-repository']

        if self.lsb_release['Release'] >= 11.10:
            command += ['-y']
            if keyserver != None:
                command += ['-k', keyserver]

        command += [repo]

        rc, report = testlib.cmd(command)
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        if invert_match == False:
            result = "Couldn't find '%s' in report" % string
            self.assertTrue(string in report, result + report)
        else:
            result = "Found '%s' in report" % string
            self.assertFalse(string in report, result + report)

    def _search_fp(self, fingerprint, invert_match = False):
        '''Search for a specific fingerprint in the apt keyring'''

        string = "fpr:::::::::%s:" % fingerprint

        expected_rc = 0
        rc, report = testlib.cmd(['gpg', '--no-default-keyring', '--no-options',
                                  '--homedir', '/tmp', '--keyring', '/etc/apt/trusted.gpg',
                                  '--list-keys', '--fingerprint', '--batch', '--with-colons'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        if invert_match == False:
            result = "Couldn't find '%s' in report" % string
            self.assertTrue(string in report, result + report)
        else:
            result = "Found '%s' in report" % string
            self.assertFalse(string in report, result + report)

    def test_ppa(self):
        '''Test adding a PPA'''
        self._call_aar(self.ppa, self.ppa_id)
        self._search_fp(self.ppa_fp)

    def test_local_keyserver(self):
        '''Test fetching key from local server'''
        self.server = WebServer(('', self.port), WebServerHandler)
        self.server.data = self.ppa_key

        # Start a new thread for the web server
        self.server_thread = threading.Thread(target=self.server.handle_request)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

        # Can't specify keyserver on natty and earlier
        if self.lsb_release['Release'] < 11.10:
            testlib.config_replace(self.hosts, "127.0.0.1 keyserver.ubuntu.com", True)

        self._call_aar(self.ppa, self.ppa_id, keyserver = self.keyserver)
        self._search_fp(self.ppa_fp)

        self.server.server_close()
        self.server = None

    def test_wrong_key(self):
        '''Test fetching wrong key from local server'''
        self.server = WebServer(('', self.port), WebServerHandler)
        self.server.data = self.wrong_ppa_key

        # Start a new thread for the web server
        self.server_thread = threading.Thread(target=self.server.handle_request)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

        # Can't specify keyserver on natty and earlier
        if self.lsb_release['Release'] < 11.10:
            testlib.config_replace(self.hosts, "127.0.0.1 keyserver.ubuntu.com", True)

        self._call_aar(self.ppa, self.ppa_id, keyserver = self.keyserver)
        self._search_fp(self.wrong_ppa_fp, invert_match = True)

        self.server.server_close()
        self.server = None


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
