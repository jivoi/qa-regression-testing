#!/usr/bin/python
#
#    test-nginx.py quality assurance test script for nginx
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
# QRT-Packages: nginx elinks
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py testlib_ssl.py 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.
'''

import os
import shutil
import subprocess
import sys
import unittest
import testlib
import testlib_httpd
import testlib_ssl

use_private = True
try:
    from private.qrt.nginx import NginxPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"


class NginxTest(testlib_httpd.HttpdCommon):
    '''Test nginx.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

        if self.lsb_release['Release'] < 15.04:
            self.document_root = "/usr/share/nginx/html"
        else:
            self.document_root = "/var/www/html"

        self.html_page = os.path.join(self.document_root, "test.html")

        self.default_vhost = "/etc/nginx/sites-available/default"
        self.ssl_crt = "/etc/nginx/cert.pem"
        self.ssl_key = "/etc/nginx/cert.key"

        self.pidfile = "/var/run/nginx.pid"

        self.daemon = testlib.TestDaemon("/etc/init.d/nginx")
        self.daemon.restart()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.html_page):
            os.unlink(self.html_page)
        if os.path.exists(self.ssl_crt):
            os.unlink(self.ssl_crt)
        if os.path.exists(self.ssl_key):
            os.unlink(self.ssl_key)

        testlib.config_restore(self.default_vhost)

    def test_daemons(self):
        '''Test daemon'''
        self.assertTrue(testlib.check_pidfile("nginx", self.pidfile))

    def test_http(self):
        '''Test http'''
        self._test_url("http://localhost/", "Welcome to nginx")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_https(self):
        '''Test https'''

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem,
         cacert_pem) = testlib_ssl.gen_ssl()
        shutil.copy(srvkey_pem, self.ssl_key)
        shutil.copy(srvcert_pem, self.ssl_crt)
        testlib.recursive_rm(tmpdir)

        testlib.config_replace(self.default_vhost, '''
server {
	listen 443;
	server_name localhost;

	root %s;
	index index.html index.htm index.nginx-debian.html;

	ssl on;
	ssl_certificate cert.pem;
	ssl_certificate_key cert.key;

	ssl_session_timeout 5m;

	ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers "HIGH:!aNULL:!MD5 or HIGH:!aNULL:!MD5:!3DES";
	ssl_prefer_server_ciphers on;

	location / {
		try_files $uri $uri/ =404;
	}
}
''' % self.document_root, append=True)

        self.daemon.restart()

        self._test_url("https://localhost/", "Welcome to nginx")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("https://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_proxy(self):
        '''Test proxy'''

        # Example using resolver from here:
        # https://www.jethrocarr.com/2013/11/02/nginx-reverse-proxies-and-dns-resolution/

        testlib.config_replace(self.default_vhost, '''
server {
	listen 80;
	server_name localhost;

	location / {
		resolver 8.8.8.8;
		set $backend_upstream "http://archive.ubuntu.com:80";
		proxy_pass $backend_upstream;
	}
}
''', append=False)

        self.daemon.restart()

        self._test_url("http://localhost/", "Index of")


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(NginxTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(NginxPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
