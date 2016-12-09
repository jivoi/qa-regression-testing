#!/usr/bin/python
#
#    test-curl.py quality assurance test script for curl
#    Copyright (C) 2009-2016 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release curl  && ./test-curl.py -v'
'''

# QRT-Depends: testlib_ssl.py
# QRT-Packages: curl ca-certificates gnutls-bin python-pycurl

import unittest, sys
import base64
import socket
import testlib
import testlib_ssl
import time
import threading
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer
import os
import pycurl
import cStringIO

class WebServer(HTTPServer):
    '''HTTPServer class with extra parameters.'''
    data = ''

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class WebServerHandler(BaseHTTPRequestHandler):
    '''A simple web server to test curl.'''
    def do_HEAD(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

    def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(self.server.data)

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    '''A simple tcp server to test curl pop3'''
    def handle(self):
        self.request.send("+OK POP3 mail v1.0 server ready\n\n")
        data = "Bogus"
        while data:
            data = self.request.recv(1024).strip().replace('\n', 'X').replace('\r', 'X')
            if data[:4] in ["USER", "PASS", "QUIT"]:
                self.request.send("+OK\r\n")
            if data.startswith("RETR"):
                self.request.send("+OK\r\nRequest was: %s\r\n.\r\n" % data)

class HackTCPRequestHandler(SocketServer.BaseRequestHandler):
    '''A simple tcp server to test curl pop3 with CVE-2013-0249'''

    # Based on http://i.volema.com/pop3d.py
    def handle(self):
        self.request.send("+OK POP3 mail v1.0 server ready\n\n")
        data = "Bogus"
        while data:
            data = self.request.recv(1024).strip().replace('\n', 'X').replace('\r', 'X')
            if data[:4] in ["USER", "dXNl", "QUIT"]:
                self.request.send("+OK\r\n")
            if data[:4] in ["QUIT"]:
                self.request.send("+OK\r\n")
            if data[:4] in ["PASS"]:
                self.request.send("-ERR 999\r\n")
            if data[:4] in ["CAPA"]:
                resp =  '+OK List of capabilities follows\n'
                resp += 'SASL DIGEST-MD5\n'
                resp += 'IMPLEMENTATION dumbydumb POP3 server\n'
                resp += '.\n'
                self.request.send(resp)
            if data[:4] in ["AUTH"]:
                realm = 'A'*128
                payload = 'realm="%s",nonce="OA6MG9tEQGm2hh",qop="auth",algorithm=md5-sess,charset=utf-8' % realm
                resp = '+ '+base64.b64encode(payload)+'\n'
                self.request.send(resp)
            if data.startswith("RETR"):
                self.request.send("+OK\r\nRequest was: %s\r\n.\r\n" % data)

class WebServerRedirectHandler(BaseHTTPRequestHandler):
    '''A simple web server to test curl that redirects.'''
    def do_HEAD(self):
            self.send_response(301)
            self.send_header('Location', self.server.data)
            self.end_headers()

    def do_GET(self):
            self.do_HEAD()

class CurlTest(testlib.TestlibCase):
    '''Test curl.'''
    server = None
    tcpserver = None
    server_thread = None
    tcpserver_thread = None
    server_redirect = None
    server_redirect_thread = None

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = None
        self.topdir = os.getcwd()
        self.listener = None
        self.hosts_file = "/etc/hosts"

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.server:
            self.server.server_close()

        if self.tcpserver:
            self.tcpserver.shutdown()
            self.tcpserver = None

        if self.server_redirect:
            self.server_redirect.server_close()

        if self.listener:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)
            self.listener = None

        if self.tempdir and os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        testlib.config_restore(self.hosts_file)

        os.chdir(self.topdir)

    def _call_curl(self, url, string, expected_rc = 0, invert_match = False,
                   check_ssl=True, cacert=None, force_ssl3=False):
        '''Call curl and check for a specific string in output'''

        command = ['curl']
        if check_ssl == False:
            command.append('-k')

        if cacert != None:
            command.append('--cacert')
            command.append(cacert)

        if force_ssl3:
            command.append('-3')

        command.append('-L')
        command.append(url)

        rc, report = testlib.cmd(command)
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        if invert_match == False:
            result = "Couldn't find '%s' in report" % string
            self.assertTrue(string in report, result + report)
        else:
            result = "Found '%s' in report" % string
            self.assertFalse(string in report, result + report)

    def _call_pycurl(self, url, string, expected_rc = 0, invert_match = False,
                     check_ssl=True, check_host=True, cacert=None):
        '''Call pycurl and check for a specific string in output'''

        rc = 0
        errstr = ""
        buf = cStringIO.StringIO()

        c = pycurl.Curl()
        c.setopt(c.URL, url)
        c.setopt(c.WRITEFUNCTION, buf.write)

        if check_host == True:
            check_host_val = 2
        else:
            check_host_val = 0

        c.setopt(c.SSL_VERIFYPEER, check_ssl)
        c.setopt(c.SSL_VERIFYHOST, check_host_val)

        if cacert != None:
            c.setopt(c.CAINFO, cacert)

        try:
            c.perform()
        except pycurl.error, error:
            rc, errstr = error

        report = errstr + buf.getvalue()
        buf.close()

        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)

        if invert_match == False:
            result = "Couldn't find '%s' in report" % string
            self.assertTrue(string in report, result + report)
        else:
            result = "Found '%s' in report" % string
            self.assertFalse(string in report, result + report)

    def test_file(self):
        '''Test fetching a file'''
        self._call_curl('file:///etc/hosts', '127.0.0.1')

    def test_url(self):
        '''Test fetching an html file'''
        self.server = WebServer(('', 5080), WebServerHandler)
        self.server.data = "This is a test"

        # Start a new thread for the web server
        self.server_thread = threading.Thread(target=self.server.handle_request)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

        self._call_curl('http://127.0.0.1:5080', 'This is a test')

        self.server.server_close()

    def test_redirect_1(self):
        '''Test fetching an html file after being redirected'''
        # Start a web server with a static file
        self.server = WebServer(('', 5080), WebServerHandler)
        self.server.data = "This is a test"
        self.server_thread = threading.Thread(target=self.server.handle_request)
        self.server_thread.setDaemon(True)
        self.server_thread.start()

        # Start a second web server with a redirect to the first web server
        self.server_redirect = WebServer(('', 5090), WebServerRedirectHandler)
        self.server_redirect.data = "http://127.0.0.1:5080"
        self.server_redirect_thread = threading.Thread(target=self.server_redirect.handle_request)
        self.server_redirect_thread.setDaemon(True)
        self.server_redirect_thread.start()

        self._call_curl('http://127.0.0.1:5090', 'This is a test')

        self.server.server_close()
        self.server_redirect.server_close()

    def test_redirect_2(self):
        '''Test fetching a local file after being redirected (CVE-2009-0037)'''
        # Start a web server with a redirect to a local file
        self.server_redirect = WebServer(('', 5090), WebServerRedirectHandler)
        self.server_redirect.data = "file:///etc/hosts"
        self.server_redirect_thread = threading.Thread(target=self.server_redirect.handle_request)
        self.server_redirect_thread.setDaemon(True)
        self.server_redirect_thread.start()

        if self.lsb_release['Release'] >= 15.04:
            message = 'Protocol "file" not supported or disabled in libcurl'
        else:
            message = 'Protocol file not supported or disabled in libcurl'

        # Make sure we get an error return code
        self._call_curl('http://127.0.0.1:5090', message, expected_rc = 1)

        self.server_redirect.server_close()

    def test_pop3(self):
        '''Test pop3'''

        # FIXME: this doesn't work on saucy for some reason
        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Doesn't work on Saucy+")

        self.tcpserver = ThreadedTCPServer(('', 5110), ThreadedTCPRequestHandler)

        # Start a new thread for the TCP server
        self.tcpserver_thread = threading.Thread(target=self.tcpserver.serve_forever)
        self.tcpserver_thread.setDaemon(True)
        self.tcpserver_thread.start()

        self._call_curl('pop3://127.0.0.1:5110/1',
                        'Request was: RETR 1')

        self.tcpserver.shutdown()

    def test_cve_2013_0249(self):
        '''Test CVE-2013-0249'''

        if self.lsb_release['Release'] >= 16.04:
            return self._skipped("Doesn't work on Xenial+")

        self.tcpserver = ThreadedTCPServer(('', 5120), HackTCPRequestHandler)

        # Start a new thread for the TCP server
        self.tcpserver_thread = threading.Thread(target=self.tcpserver.serve_forever)
        self.tcpserver_thread.setDaemon(True)
        self.tcpserver_thread.start()

        # Precise and earlier don't support this at all
        if self.lsb_release['Release'] == 12.04:
            expected = 67
            expected_str = 'Access denied'
        else:
            expected = 56
            expected_str = 'response reading failed'

        self._call_curl('pop3://x:x@127.0.0.1:5120/1',
                        expected_str, expected)

        self.tcpserver.shutdown()

    def test_cve_2012_0036(self):
        '''Test CVE-2012-0036'''

        # FIXME: this doesn't work on saucy for some reason
        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Doesn't work on Saucy+")

        self.tcpserver = ThreadedTCPServer(('', 5111), ThreadedTCPRequestHandler)

        # Start a new thread for the web server
        self.tcpserver_thread = threading.Thread(target=self.tcpserver.serve_forever)
        self.tcpserver_thread.setDaemon(True)
        self.tcpserver_thread.start()

        self._call_curl('pop3://127.0.0.1:5111/1%0d%0aDELE%201',
                        'RETR 1XXDELE 1',
                        expected_rc = 3,
                        invert_match=True)

        self._call_curl('pop3://127.0.0.1:5111/1%0d%0aDELE%201',
                        'URL using bad/illegal format',
                        expected_rc = 3)

        self.tcpserver.shutdown()

    def test_http(self):
        '''Test http (ubuntu.com)'''
        self._call_curl("http://www.ubuntu.com/", 'Canonical')

    def test_https_verify(self):
        '''Test https verify (launchpad.net)'''
        self._call_curl("https://launchpad.net/", 'canonical')

    def test_cve_2013_4545_regression(self):
        '''Test CVE-2013-4545 regression (LP: #1258366)'''

        # Don't use a domain we don't own
        #self._call_curl("https://www.example.com/", 'was not OK', expected_rc=51)
        #self._call_curl("https://www.example.com/", 'Example Domain', check_ssl=False)

        # This cert should be valid, but contain a hostname mismatch
        ip_addr = socket.gethostbyname('launchpad.net')
        testlib.config_replace(self.hosts_file, "%s www.bank.com" % ip_addr, True)

        if self.lsb_release['Release'] <= 12.04:
            error = 'was not OK'
        elif self.lsb_release['Release'] <= 15.04:
            error = 'no alternative certificate subject name matches'
        else:
            error = 'does not match target host name'


        force_ssl3=False

        self._call_curl("https://www.bank.com/", error, expected_rc=51,
                        force_ssl3=force_ssl3)
        self._call_curl("https://www.bank.com/", 'canonical',
                        check_ssl=False, force_ssl3=force_ssl3)


    def test_https_selfsigned(self):
        '''Test https self-signed with curl'''
        (self.tempdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        # fire up a server
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4443 --x509keyfile %s --x509certfile %s --x509cafile %s >/dev/null 2>&1' % (srvkey_pem, srvcert_pem, cacert_pem)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        # Make sure it doesn't verify
        if self.lsb_release['Release'] <= 15.04:
            error = 'SSL certificate problem'
        else:
            error = 'server certificate verification failed'
        self._call_curl("https://127.0.0.1:4443/", error, expected_rc=60)

        # Now try again, ignoring the error
        self._call_curl("https://127.0.0.1:4443/", 'Session ID', check_ssl=False)

        # Now try again, with the ca cert. Should give invalid hostname.
        self._call_curl("https://127.0.0.1:4443/", 'does not match target host name',
                        expected_rc = 51, cacert = cacert_pem)

        if self.listener:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)
            self.listener = None

    def test_https_selfsigned_pycurl(self):
        '''Test https self-signed with pycurl'''
        (self.tempdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        # fire up a server
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4443 --x509keyfile %s --x509certfile %s --x509cafile %s >/dev/null 2>&1' % (srvkey_pem, srvcert_pem, cacert_pem)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        # Make sure it doesn't verify
        self._call_pycurl("https://127.0.0.1:4443/", 'certificate verification failed', expected_rc=60)

        # Now try again, host name should fail
        self._call_pycurl("https://127.0.0.1:4443/", 'does not match target host name',
                          expected_rc = 51, check_ssl=False)

        # Now try again, with all checks disabled
        self._call_pycurl("https://127.0.0.1:4443/", 'Session ID', check_ssl=False, check_host=False)

        # Now try again, with the ca cert. Should give invalid hostname.
        self._call_pycurl("https://127.0.0.1:4443/", 'does not match target host name',
                        expected_rc = 51, cacert = cacert_pem)

        # Now try again, with the ca cert, and no cert validation. Should still give invalid hostname.
        self._call_pycurl("https://127.0.0.1:4443/", 'does not match target host name',
                        expected_rc = 51, check_ssl = False, cacert = cacert_pem)

        if self.listener:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)
            self.listener = None


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CurlTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
