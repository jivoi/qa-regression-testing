#!/usr/bin/python
#
#    test-requests.py quality assurance test script for requests
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
# QRT-Packages: python-requests python3-requests

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''


import os
import subprocess
import sys
import unittest
import testlib
import threading
import tempfile
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer

try:
    from private.qrt.requests import PrivateRequestsTest
except ImportError:
    class PrivateRequestsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class WebServer(HTTPServer):
    '''HTTPServer class with extra parameters.'''
    data = ''

class WebServerHandler(BaseHTTPRequestHandler):
    '''A simple web server to test requests.'''

    def do_GET(self):
        if self.path.startswith('/redirect/'):
            self.send_response(303)
            self.send_header('Location', self.path[10:])
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            s = 'host: {}\n'.format(self.headers.get('Host'))
            self.wfile.write(s.encode())
            s = 'auth: {}\n'.format(self.headers.get('Authorization'))
            self.wfile.write(s.encode())

class RequestsTest(testlib.TestlibCase, PrivateRequestsTest):
    '''Test requests.'''

    server = None
    server_thread = None

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="qrt-")
        self.cwd = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.server:
            self.server.shutdown()
            self.server=None

        os.chdir(self.cwd)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _write_script(self, filename, data):
        '''Writes out a shell script into the temporary directory'''

        fullname = os.path.join(self.tempdir, filename)
        f = open(fullname, 'w')
        f.write(data)
        f.close()
        os.chmod(fullname, 0755)
        return fullname

    def _check_script_results(self, script, results=None, expected=None,
                              args=[], invert=False, exe="python"):
        '''Run a python script, check if results contain text'''

        rc, report = testlib.cmd(['/usr/bin/%s' % exe] + args + [script])

        if expected != None:
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        if results != None:
            if invert == False:
                warning = 'Could not find "%s"\n' % results
                self.assertTrue(results in report, warning + report)
            else:
                warning = 'Found "%s"\n' % results
                self.assertFalse(results in report, warning + report)

    def test_cve_2014_1829(self):
        '''Test CVE-2014-1829'''

        self.server = WebServer(('', 5080), WebServerHandler)
        self.server.data = "This is a test"

        # Start a new thread for the web server
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

        script = '''import requests

response = requests.get("http://localhost:5080/redirect/http://127.0.0.42:5080/",
                        auth=('user', 'secretpass'))
print(response.text)
'''

        filename = self._write_script('cve-2014-1829.py', script)
        self._check_script_results(filename, 'auth: None', exe="python2")
        self._check_script_results(filename, 'auth: None', exe="python3")

        self.server.shutdown()

    def test_http(self):
        '''Test http (ubuntu.com)'''

        script = '''import requests

response = requests.get("http://www.ubuntu.com/")
print(response.text)
'''

        filename = self._write_script('ubuntudotcom.py', script)
        self._check_script_results(filename, 'Canonical', exe="python2")
        self._check_script_results(filename, 'Canonical', exe="python3")

    def test_https_verify(self):
        '''Test https verify (launchpad.net)'''

        script = '''import requests

response = requests.get("https://launchpad.net/")
print(response.text.encode('utf-8'))
'''

        filename = self._write_script('launchpad.py', script)
        self._check_script_results(filename, 'canonical', exe="python2")
        self._check_script_results(filename, 'canonical', exe="python3")



if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
