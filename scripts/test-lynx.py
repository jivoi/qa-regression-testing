#!/usr/bin/python
#
#    test-lynx.py quality assurance test script for lynx
#    Copyright (C) 2012 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
  How to run in a clean virtual machine:
    1. apt-get -y install lynx-cur
    2. ./test-lynx.py -v (as non-root)

  Debugging:
    lynx -tlog -trace -dump http... # creates ~/Lynx.trace
'''

# QRT-Depends: data testlib_ssl.py
# QRT-Packages: lynx-cur ca-certificates lsb-release gnutls-bin

import unittest, sys, os
import tempfile
import testlib
import testlib_ssl
import time


class TestURLs(testlib.TestlibCase):
    '''Test viewing of various files'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.exes = ['lynx']
        self.tempdir = None
        self.topdir = os.getcwd()
        os.environ['LYNX_CFG'] = ""
        os.environ['LYNX_TRACE_FILE'] = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.tempdir and os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)
        if os.environ['LYNX_TRACE_FILE'] != "":
            trace = os.path.expanduser("~/%s" % os.environ['LYNX_TRACE_FILE'])
            if os.path.exists(trace):
                os.unlink(trace)
        os.chdir(self.topdir)

    def _lynx_cmd(self, url, search='', expected=0, extra_args=[]):
        '''Execute lynx with the given url'''
        command = ['lynx', '-dump']
        if len(extra_args) > 0:
            command += extra_args
        rc, report = testlib.cmd(command + [url])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if search != '':
            result = 'Could not find \'%s\'\n' % (search)
            self.assertTrue(search in report, result + report)

    def test_file(self):
        '''Test file'''
        self._lynx_cmd("./data/well_formed_xhtml1.0.html", search='Sample content')

    def test_ftp(self):
        '''Test http (ftp.debian.org)'''
        self._lynx_cmd("ftp://ftp.debian.org/", search='Current directory is /')
        self._lynx_cmd("ftp://ftp.debian.org/", search='ftp://ftp.debian.org/debian')

    def test_http(self):
        '''Test http (ubuntu.com)'''
        self._lynx_cmd("http://www.ubuntu.com/")

    def test_http_intl(self):
        '''Test http (www.google.de)'''
        self._lynx_cmd("http://www.google.de/")
        self._lynx_cmd("./data/www.google.de.html", search='Datenschutz')

    def test_https_verify(self):
        '''Test https verify (launchpad.net)'''
        self._lynx_cmd("https://launchpad.net/")

    def test_https_selfsigned(self):
        '''Test https self-signed'''
        (self.tempdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        # fire up a server
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4443 --x509keyfile %s --x509certfile %s --x509cafile %s >/dev/null 2>&1' % (srvkey_pem, srvcert_pem, cacert_pem)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        # Make sure it doesn't verify
        self._lynx_cmd("https://127.0.0.1:4443/", expected=1)

        # Now try again, ignoring the error
        self.lynx_cfg = os.path.join(self.tempdir, "lynx.cfg")
        contents = '''FORCE_SSL_PROMPT:yes\n'''
        testlib.config_replace(self.lynx_cfg, contents)
        os.environ['LYNX_CFG'] = self.lynx_cfg
        self._lynx_cmd("https://127.0.0.1:4443/", expected=0)

        os.environ['LYNX_TRACE_FILE'] = "testlib-Lynx.trace"
        self._lynx_cmd("https://127.0.0.1:4443/", expected=0,
                       extra_args=['-trace', '-tlog'])
        trace = os.path.expanduser("~/%s" % os.environ['LYNX_TRACE_FILE'])
        self.assertTrue(os.path.exists(trace), "Could not find '%s'" % trace)

        results = open(trace).read()
        terms = ['HTParsePort 4443',
                 'Validating CNs in',
                 'ssl_host',
                 'cert_host',
                 'UNVERIFIED connection to 127.0.0.1 (cert=CN<server>)',
                 'Certificate issued by:']
        for search in terms:
            self.assertTrue(search in results, "Could not fine '%s' in:\n%s" % (search, results))

        # CVE-2012-5821
        search = 'SSL error:self signed certificate-Continue?'
        self.assertTrue(search in results, "Could not fine '%s' in:\n%s" % (search, results))

        if self.listener:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)

    def test_CVE_2010_2810(self):
        '''Test CVE-2010-2810'''
        self.tempdir = tempfile.mkdtemp()
        crash = os.path.join(self.tempdir, "crash.html")
        # From scripts/test-lynx.py
        contents = '''<a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AA%A/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a> 
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
        <a href="http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">EXPLOIT</a>
'''
        testlib.config_replace(crash, contents)
        self._lynx_cmd(crash, search='25. http://AAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/')

    def test_https_badkey(self):
        '''Test https mismatched keys'''
        (self.tempdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()

        # fire up a server
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /usr/bin/gnutls-serv --http -p 4443 --x509keyfile %s --x509certfile %s --x509cafile %s >/dev/null 2>&1' % (clientkey_pem, srvcert_pem, cacert_pem)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        # Make sure it doesn't verify
        self._lynx_cmd("https://127.0.0.1:4443/", expected=1)

        if self.listener:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)

if __name__ == '__main__':
    suite = unittest.TestSuite()

    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestFiles))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestURLs))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
