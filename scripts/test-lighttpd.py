#!/usr/bin/python
#
#    test-lighttpd.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
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
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get remove --purge lighttpd
    $ sudo apt-get -y install lighttpd elinks ssl-cert openssl php5-cgi

  NOTE:
    php/fastcgi is skipped on dapper and edgy because the test hangs (maybe
      because of difference between python2.4 and python 2.5?)

  TODO:
    SSI
    htaccess
    virtual hosts
    perl (broken, see test_cgi)
    ...
'''

# QRT-Depends: testlib_httpd.py testlib_ssl.py
# QRT-Packages: lighttpd elinks ssl-cert openssl php5-cgi
# QRT-Privilege: root

import unittest
import os
import testlib
import testlib_httpd
import testlib_ssl
import time
import sys

class BasicTest(testlib_httpd.HttpdCommon):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        self._set_initscript("/etc/init.d/lighttpd")
        testlib_httpd.HttpdCommon._setUp(self)
        self.ssl_pem = "/etc/lighttpd/server.pem"
        self.fastcgi_conf = "/etc/lighttpd/conf-available/10-fastcgi.conf"

    def tearDown(self):
        '''Shutdown methods'''
        self._disable_mod("fastcgi")
        self._disable_mod("cgi")
        self._disable_mod("ssl")
        testlib_httpd.HttpdCommon._tearDown(self)
        if os.path.exists(self.ssl_pem):
            os.unlink(self.ssl_pem)
        testlib.config_restore(self.fastcgi_conf)

    # override testlib_httpd.HttpdCommon._disable_mod()
    def _disable_mod(self, mod):
        rc, report = testlib.cmd(['lighty-disable-mod', mod])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._reload()
        time.sleep(2)

    # override testlib_httpd.HttpdCommon._enable_mod()
    def _enable_mod(self, mod):
        rc, report = testlib.cmd(['lighty-enable-mod', mod])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._reload()
        time.sleep(2)

    def test_daemons(self):
        '''Test daemon'''
        pidfile = "/var/run/lighttpd.pid"
        self.assertTrue(testlib.check_pidfile("lighttpd", pidfile))

    def test_http(self):
        '''Test http'''
        self._test_url("http://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_cgi(self):
        '''Test cgi'''
        self._enable_mod("cgi")

        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url("http://localhost/" + \
                       os.path.basename(self.php_page), test_str)

	# for some reason this doesn't work, yet when trying the output alone,
        # it does
        #test_str = testlib_httpd.create_perl_script(self.cgi_page)
        #self._test_url("http://localhost/cgi-bin/" + \
        #               os.path.basename(self.cgi_page), test_str)

    def test_ssl(self):
        '''Test https'''
        tmpdir, pem = testlib_ssl.gen_pem()
        os.rename(pem, self.ssl_pem)
        testlib.recursive_rm(tmpdir)

        self._enable_mod("ssl")

        self._test_url("https://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("https://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_php(self):
        '''Test php (fastcgi)'''
        # TODO: figure out why test hangs on dapper and edgy
        if self.lsb_release['Release'] < 7.04:
            return self._skipped()

        if self.lsb_release['Release'] < 7.10:
            conf = '''
server.modules   += ( "mod_fastcgi" )
fastcgi.server    = ( ".php" => 
	((
		"bin-path" => "/usr/bin/php5-cgi",
		"socket" => "/tmp/php.socket",
		"max-procs" => 2,
		"idle-timeout" => 20,
		"bin-environment" => ( 
			"PHP_FCGI_CHILDREN" => "4",
			"PHP_FCGI_MAX_REQUESTS" => "10000"
		),
		"bin-copy-environment" => (
			"PATH", "SHELL", "USER"
		),
		"broken-scriptfilename" => "enable"
	))
)
'''
            testlib.config_replace(self.fastcgi_conf, conf)

        self._enable_mod("fastcgi")

        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url("http://localhost/" + \
                       os.path.basename(self.php_page), test_str)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
