#!/usr/bin/python
#
#    test-libsoup2.4.py quality assurance test script for libsoup2.4
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: uzbl socat lynx-cur
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_http-test-server.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-libsoup2.4.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-libsoup2.4.py -v'

    NOTES:
    - uzbl usage from http://www.uzbl.org/ and http://www.uzbl.org/wiki/dump
    - requires X

    TODO:
    This script doesn't have to do a lot since libsoup has an in build test
    suite. That said, here are a few things that would be nice:
    - basic and digest auth (see /usr/share/doc/uzbl/README for how to use
      uzbl to do authentication)
    - proxy
    - maybe move some of this out to testlib_uzbl.py
    - go through http://live.gnome.org/LibSoup
'''


import unittest, sys, os
import shutil
import tempfile
import testlib
import time

try:
    from private.qrt.Pkg import PrivatePkgTest
except ImportError:
    class PrivatePkgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class SoupUzblTest(testlib.TestlibCase, PrivatePkgTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.uzbl_files_dir = "/tmp"
        self.uzbl_socket = None
        self.uzbl_fifo = None
        self.uzbl_listener = None
        self.exe = "/usr/bin/uzbl"
        # self.exe = "/usr/bin/uzbl-core" # when to use this?

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        self.www_listener = None
        self.www_dir = os.path.join(self.tmpdir, 'www')
        self.www_port = 8008
        self.www_url = "http://127.0.0.1:%d/" % self.www_port
        os.mkdir (self.www_dir)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.uzbl_listener != None:
            os.kill(self.uzbl_listener, 15)
            os.waitpid(self.uzbl_listener, 0)

        # make sure they are dead fur realz (needed for at least Lucid)
        testlib.cmd(['killall', 'uzbl'])
        testlib.cmd(['killall', '-9', 'uzbl'])
        testlib.cmd(['killall', 'uzbl-core'])
        testlib.cmd(['killall', '-9', 'uzbl-core'])

        if self.www_listener != None:
            os.kill(self.www_listener, 15)
            os.waitpid(self.www_listener, 0)

        if self.uzbl_socket != None and os.path.exists(self.uzbl_socket):
            os.unlink(self.uzbl_socket)

        if self.uzbl_fifo != None and os.path.exists(self.uzbl_fifo):
            os.unlink(self.uzbl_fifo)

        if os.path.isdir(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _find_files(self):
        '''Find uzbl file'''
        for f in os.listdir(self.uzbl_files_dir):
            path = os.path.join(self.uzbl_files_dir, f)
            if f.startswith('uzbl_fifo_'):
                self.uzbl_fifo = os.path.join(path)
                #print "fifo: %s" % self.uzbl_fifo
            elif f.startswith('uzbl_socket_'):
                self.uzbl_socket = os.path.join(path)
                #print "socket: %s" % self.uzbl_socket

            if self.uzbl_socket != None and self.uzbl_fifo != None:
                break

    def _start_server(self):
        '''Start an http server'''
        httpd = os.path.join(self.tmpdir, "httpd")
        shutil.copy("./testlib_http-test-server.py", httpd)

        self.www_listener = os.fork()
        if self.www_listener == 0:
            args = ['/bin/sh', '-c', 'exec python %s -p %d -d %s >/dev/null 2>&1' % (httpd, self.www_port, self.www_dir)]
            os.execv(args[0], args)
            sys.exit(0)

    def _start_uzbl(self, url):
        '''Start uzbl and locate its socket and fifo files'''
        self._find_files()
        self.assertTrue(self.uzbl_socket == None and self.uzbl_fifo == None, "Found (stale) uzbl files. Please close any running uzbl processes and remove '%s/uzbl_*'" % self.uzbl_files_dir)


        self.uzbl_listener = os.fork()
        if self.uzbl_listener == 0:
            args = ['/bin/sh', '-c', 'exec %s -u %s >/dev/null 2>&1' % (self.exe, url)]
            os.execv(args[0], args)
            sys.exit(0)

        # wait until uzbl is initialized
        count = 0
        self._find_files()
        while self.uzbl_socket == None and self.uzbl_fifo == None and count < 50:
            self._find_files()
            count += 1
            time.sleep(0.2)

    def _fetch_url(self, url, html=True, search=None, timeout=30):
        '''Fetch url'''
        self.assertTrue(html == True or search != None, "Must have a search string for text")

        self._start_uzbl(url)
        self.assertTrue(self.uzbl_socket != None, "Don't have a uzbl socket")

        report = "\nLOAD_PROGRESS 0"
        count = 0
        while "LOAD_PROGRESS" in report and count < timeout:
            rc, report = testlib.cmd_pipe(['echo', 'js document.documentElement.outerHTML'], ['socat', '-', 'unix-connect:"%s"' % self.uzbl_socket])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            count += 1
            self.assertTrue(count < timeout, "Could not fetch page after '%d' seconds" % timeout)
            time.sleep(1)

        # make sure uzbl is done loading
        time.sleep(1)

        # now that LOAD progress is not in there, we should have the page
        self.assertTrue(self.uzbl_socket != None, "Don't have a uzbl socket")
        rc, report = testlib.cmd_pipe(['echo', 'js document.documentElement.outerHTML'], ['socat', '-', 'unix-connect:"%s"' % self.uzbl_socket])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        out = report

        if not html:
            rc, report = testlib.cmd_pipe(['echo', out], ['lynx', '-dump', '-stdin'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            out = report

        if search == None:
            search = "</html>"
        self.assertTrue(search in out, "Could not find '%s' in:\n%s" % (search, out))
        return out

    def test_http(self):
        '''Test http://www.ubuntu.com'''
        out = self._fetch_url("http://www.ubuntu.com", search="Ubuntu")

    def test_http_nonexistent(self):
        '''Test nonexistent url'''
        search = "Cannot resolve hostname"
        if self.lsb_release['Release'] < 11.04:
            search = "<html></html>"
        elif self.lsb_release['Release'] < 11.10:
            search = "<html><head></head><body></body></html>"
        out = self._fetch_url("http://www.ubuntu.com.nonexistent", search=search)

    def test_https(self):
        '''Test https://launchpad.net'''
        out = self._fetch_url("https://launchpad.net", search="Launchpad")

    def test_200(self):
        '''Test 200'''
        self._start_server()
        out = self._fetch_url(self.www_url + "200", search="200")

    def test_401(self):
        '''Test 401'''
        self._start_server()
        out = self._fetch_url(self.www_url + "401", search="401")

    def test_403(self):
        '''Test 403'''
        self._start_server()
        out = self._fetch_url(self.www_url + "403", search="403")

    def test_404(self):
        '''Test 404'''
        self._start_server()
        out = self._fetch_url(self.www_url + "404", search="404")

    def test_500(self):
        '''Test 500'''
        self._start_server()
        out = self._fetch_url(self.www_url + "500", search="500")

if __name__ == '__main__':
    # simple
    unittest.main()

