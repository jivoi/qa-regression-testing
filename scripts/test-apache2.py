#!/usr/bin/python
#
#    test-apache2.py quality assurance test script
#    Copyright (C) 2008-2015 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
    $ sudo apt-get remove --purge apache2-*
    $ sudo apt-get install apache2-mpm-worker | apache2-mpm-event | apache2-mpm-prefork | apache2-mpm-itk | apache2-mpm-perchild
    $ sudo apt-get -y install elinks ssl-cert openssl lsb-release libapache2-svn subversion davfs2 sudo python-pexpect

  If you want to include php5 tests (apache2-mpm-prefork only):
    $ sudo apt-get -y install libapache2-mod-php5

  TODO:
    SSI (with XBitHack)
    perl
    ...
'''

# xQRT-Depends: testlib_httpd.py testlib_ssl.py
# xQRT-Packages: (apache2-mpm-worker | apache2-mpm-event | apache2-mpm-prefork | apache2-mpm-itk | apache2-mpm-perchild) libapache2-svn subversion elinks ssl-cert openssl lsb-release libapache2-mod-php5 davfs2 sudo python-pexpect openssl

import unittest, subprocess
import os
import errno
import testlib
import testlib_httpd
import testlib_ssl
import tempfile
import time
import shutil
import sys
import socket
import pexpect

class BasicTest(testlib_httpd.HttpdCommon):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        self._set_initscript("/etc/init.d/apache2")
        self.envvars = "/etc/apache2/envvars"
        self.proxy_conf = "/etc/apache2/mods-available/proxy.conf"
        self.php5_mod = "/usr/lib/apache2/modules/libphp5.so"
        self.tempdir = tempfile.mkdtemp()
        if self.lsb_release['Release'] >= 13.10:
            self.default_vhost = "/etc/apache2/sites-available/000-default.conf"
            self.default_vhost_link = "/etc/apache2/sites-enabled/000-default.conf"
            self.testlib_conf = "/etc/apache2/conf-enabled/testlib.conf"
            self.charset = "/etc/apache2/conf-enabled/charset.conf"
        else:
            self.default_vhost = "/etc/apache2/sites-available/default"
            self.default_vhost_link = "/etc/apache2/sites-enabled/000-default"
            self.testlib_conf = "/etc/apache2/conf.d/testlib"
            self.charset = "/etc/apache2/conf.d/charset"

        self.mountpoint = ""

        # remove dangling symlinks in case libapache2-php5 was removed
        if not os.path.exists(self.php5_mod):
            for f in ['/etc/apache2/mods-enabled/php5.conf', '/etc/apache2/mods-enabled/php5.load']:
                if os.path.lexists(f):
                    print "removing dangling symlink: '%s'" % (f),
                    os.unlink(f)

        # ensure sites-enabled/000-default is a symlink to
        # sites-available/default, or else tests will fail.
        try:
            if os.path.abspath(os.path.join('/etc/apache2/sites-enabled/', os.readlink(self.default_vhost_link))) == self.default_vhost:
                pass
        except OSError, e:
            if e.errno == errno.ENOENT or e.errno == errno.EINVAL:
                testlib._save_backup(self.default_vhost_link)
                os.unlink(self.default_vhost_link)
                os.symlink(self.default_vhost, self.default_vhost_link)
            else:
                raise e

        testlib_httpd.HttpdCommon._setUp(self)

    def tearDown(self):
        '''Shutdown methods'''
        os.chdir('/tmp')
        if os.path.exists(self.mountpoint):
            testlib.cmd(['umount', '-f', self.mountpoint])
        if os.path.exists(self.testlib_conf):
            os.unlink(self.testlib_conf)
        if os.path.exists("/etc/davfs2/secrets"):
            testlib.config_restore("/etc/davfs2/secrets")
            os.chmod("/etc/davfs2/secrets", 0600)
        testlib.config_restore(self.charset)
        testlib.config_restore(self.proxy_conf)
        testlib.config_restore(self.default_vhost)
        testlib.config_restore(self.envvars)
        testlib.config_restore(self.default_vhost_link)

        if 'OPENSSL_DEFAULT_ZLIB' in os.environ:
            del os.environ['OPENSSL_DEFAULT_ZLIB']

        testlib_httpd.HttpdCommon._tearDown(self)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

        if os.path.exists("/etc/subversion/servers"):
            testlib.config_restore("/etc/subversion/servers")

    def _add_basic_auth_user(self, user, password, file):
        '''Add user to htpasswd for basic auth'''
        cmd = ['htpasswd', '-b']
        if not os.path.exists(file):
            cmd.append('-c')
        cmd += [file, user, password]
        (rc, report) = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_daemons(self):
        '''Test daemon'''
        if self.lsb_release['Release'] >= 13.10:
            pidfile = "/var/run/apache2/apache2.pid"
        else:
            pidfile = "/var/run/apache2.pid"
        self.assertTrue(testlib.check_pidfile("apache2", pidfile))

    def test_status(self):
        '''Test status (apache2ctl)'''
        rc, report = testlib.cmd(['apache2ctl', 'status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_http(self):
        '''Test http'''
        self._test_url("http://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_proxy_ftp(self):
        '''Test ftp proxy'''

        # Enable proxying
        testlib.config_replace(self.proxy_conf, "", append=True)
        if self.lsb_release['Release'] < 10.10:
            subprocess.call(['sed', '-i', 's/ProxyRequests Off/ProxyRequests On/', self.proxy_conf])
            subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])
        else:
            subprocess.call(['sed', '-i', "s/#ProxyVia Off/<Proxy *>" +
                                          "\\nAddDefaultCharset off" +
                                          "\\nOrder deny,allow" +
                                          "\\nAllow from all" +
                                          "\\n<\/Proxy>" +
                                          "\\nProxyRequests On/", self.proxy_conf])

        if self.lsb_release['Release'] >= 13.10:
            auth_required = 'HTTP/1.1 401 Unauthorized'
        else:
            auth_required = 'HTTP/1.1 401 Authorization Required'

        # Enable the ftp proxy module
        self._enable_mods(["proxy", "proxy_ftp"])

        print ""

        # We need a working ftp server for this. Using ftp.ubuntu.com for now.
        print "  GET (no credentials)"
        request = "GET ftp://ftp.ubuntu.com/ HTTP/1.0\n\n"
        self._test_raw(request, 'Directory of <a href="/">ftp://ftp.ubuntu.com</a>/')
        self._test_raw(request, 'HTTP/1.1 200 OK')

        print "  GET (anonymous)"
        request = "GET ftp://anonymous:test@example.com@ftp.ubuntu.com/ HTTP/1.0\n\n"
        self._test_raw(request, 'HTTP/1.1 200 OK')

        print "  401 (bad credentials)"
        request = "GET ftp://test:pass@ftp.ubuntu.com/ HTTP/1.0\n\n"
        self._test_raw(request, auth_required)

        print "  401 (anonymous no password)"
        request = "GET ftp://anonymous@ftp.ubuntu.com/ HTTP/1.0\n\n"
        self._test_raw(request, auth_required)

        print "  400 (invalid password)"
        request = "GET ftp://test:passw\000rd@ftp.ubuntu.com/ HTTP/1.0\n\n"
        search = 'Bad Request'
        self._test_raw(request, search)

    def test_ssl(self):
        '''Test https'''
        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        testlib.recursive_rm(tmpdir)

        self._test_url("https://localhost/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("https://localhost/" + \
                       os.path.basename(self.html_page), test_str)

    def test_ssl_tls_md5(self):
        '''Test whether https allows MD5'''

        # Default mod_ssl config in natty and newer disallows md5 as the
        # hash algorithm

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cipher = 'RC4-MD5'
        cmdline = 'openssl s_client -connect localhost:443 -cipher %s -CAfile %s' % (cipher, ca)

        # make sure we can connect without renegotiating
        child = pexpect.spawn(cmdline)
        time.sleep(0.2)
        child.expect('.*', timeout=2)
        time.sleep(0.2)
        child.sendline('GET / http/1.0')
        time.sleep(0.2)
        child.sendline('\n')
        time.sleep(0.2)
        search = 'HTTP/1.1 200 OK'

        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        if self.lsb_release['Release'] <= 10.10:
            result = "Attempt to access with MD5 failed"
            self.assertTrue(succeeded, result)
        else:
            result = "Attempt to access with MD5 succeeded"
            self.assertFalse(succeeded, result)

    def test_ssl_tls_v1(self):
        '''Test connecting with TLS v1.0'''

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cmdline = 'openssl s_client -tls1 -connect localhost:443 -CAfile %s' % ca

        child = pexpect.spawn(cmdline)
        time.sleep(0.2)
        child.expect('.*', timeout=2)
        time.sleep(0.2)
        child.sendline('GET / http/1.0')
        time.sleep(0.2)
        child.sendline('\n')
        time.sleep(0.2)
        search = 'HTTP/1.1 200 OK'

        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        result = "Attempt to connect with TLS v1.0 failed"
        self.assertTrue(succeeded, result)

    def test_ssl_tls_v1_1(self):
        '''Test connecting with TLS v1.1'''

        if self.lsb_release['Release'] < 12.04:
            return self._skipped("Oneiric and older don't support TLS v1.1")

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cmdline = 'openssl s_client -tls1_1 -connect localhost:443 -CAfile %s' % ca

        child = pexpect.spawn(cmdline)
        time.sleep(0.2)
        child.expect('.*', timeout=2)
        time.sleep(0.2)
        child.sendline('GET / http/1.0')
        time.sleep(0.2)
        child.sendline('\n')
        time.sleep(0.2)
        search = 'HTTP/1.1 200 OK'

        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        result = "Attempt to connect with TLS v1.1 failed"
        self.assertTrue(succeeded, result)

    def test_ssl_tls_v1_2(self):
        '''Test connecting with TLS v1.2'''

        if self.lsb_release['Release'] < 12.04:
            return self._skipped("Oneiric and older don't support TLS v1.2")

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cmdline = 'openssl s_client -tls1_2 -connect localhost:443 -CAfile %s' % ca

        child = pexpect.spawn(cmdline)
        time.sleep(0.2)
        child.expect('.*', timeout=2)
        time.sleep(0.2)
        child.sendline('GET / http/1.0')
        time.sleep(0.2)
        child.sendline('\n')
        time.sleep(0.2)
        search = 'HTTP/1.1 200 OK'

        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        result = "Attempt to connect with TLS v1.2 failed"
        self.assertTrue(succeeded, result)

    def test_ssl_tls_client_renegotiation(self):
        '''Test https (client initiated TLS renegotiation)'''

        if self.lsb_release['Release'] >= 14.10:
            return self._skipped("Test doesn't work on Utopic+")

        # CVE-2009-3555 exposed an error in the TLS protocol for
        # implementations that allow TLS renegotiation. This test
        # will test if client initiated renegotiations are allowed.
        # As a temporary work around (until openssl is updated for
        # the new TLS protocol changes) Apache disallows client
        # initiated renegotiations. Change the next line to True
        # if OpenSSL is fixed and the Apache workaround is removed.
        allow_client_renegotiation = False

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cipher = 'RC4-MD5'
        if self.lsb_release['Release'] > 10.10:
            cipher = 'RC4-SHA'

        cmdline = 'openssl s_client -connect localhost:443 -cipher %s -CAfile %s' % (cipher, ca)

        # make sure we can connect without renegotiating
        child = pexpect.spawn(cmdline)
        time.sleep(0.2)
        child.expect('.*', timeout=2)
        time.sleep(0.2)
        child.sendline('GET / http/1.0')
        time.sleep(0.2)
        child.sendline('\n')
        time.sleep(0.2)
        child.expect('HTTP/1.1 200 OK', timeout=2)

        # now connect with renegotiating
        #print cmdline
        #subprocess.call(['bash'])
        child = pexpect.spawn(cmdline)
        time.sleep(0.2)
        child.expect('.*', timeout=2)
        time.sleep(0.2)
        child.sendline('GET / http/1.0')
        time.sleep(0.2)
        child.sendline('X-ignore-me: GET /')
        time.sleep(0.2)
        child.sendline('R')
        time.sleep(0.2)
        child.expect('.*RENEGOTIATING.*', timeout=2)
        time.sleep(0.2)
        child.sendline('\n')
        time.sleep(0.2)

        search = 'HTTP/1.1 200 OK'

        failed = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            if not allow_client_renegotiation:
                failed = True
        except:
            if allow_client_renegotiation:
                failed = True

        time.sleep(0.2)
        child.kill(0)

        result = ""
        if allow_client_renegotiation:
            result = "'%s' not found\n" % (search)
        else:
            result = "'%s' found\n" % (search)
        self.assertFalse(failed, result)

    def test_cve_2012_4929_default(self):
        '''Test CVE-2012-4929 (compression default setting)'''

        # Openssl now disables compression by default
        testlib.config_replace(self.envvars, "\nexport OPENSSL_DEFAULT_ZLIB=1\n", append=True)
        os.environ['OPENSSL_DEFAULT_ZLIB']='1'

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cmdline = 'openssl s_client -tls1 -connect localhost:443 -CAfile %s' % ca

        child = pexpect.spawn(cmdline)
        time.sleep(0.2)

        search = 'Compression: NONE'
        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        result = "Could not find appropriate compression setting"
        self.assertTrue(succeeded, result)

    def test_cve_2012_4929_off(self):
        '''Test CVE-2012-4929 (compression off)'''

        # Openssl now disables compression by default
        testlib.config_replace(self.envvars, "\nexport OPENSSL_DEFAULT_ZLIB=1\n", append=True)
        os.environ['OPENSSL_DEFAULT_ZLIB']='1'

        testlib.config_replace(self.default_vhost, "\nSSLCompression off\n", append=True)

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cmdline = 'openssl s_client -tls1 -connect localhost:443 -CAfile %s' % ca

        child = pexpect.spawn(cmdline)
        time.sleep(0.2)

        search = 'Compression: NONE'
        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        result = "Could not find appropriate compression setting"
        self.assertTrue(succeeded, result)

    def test_cve_2012_4929_on(self):
        '''Test CVE-2012-4929 (compression on)'''

        # Openssl now disables compression by default
        testlib.config_replace(self.envvars, "\nexport OPENSSL_DEFAULT_ZLIB=1\n", append=True)
        os.environ['OPENSSL_DEFAULT_ZLIB']='1'

        testlib.config_replace(self.default_vhost, "\nSSLCompression on\n", append=True)

        (tmpdir, srvcert_pem, srvkey_pem, clientcert_pem, clientkey_pem, cacert_pem) = testlib_ssl.gen_ssl()
        self._prepare_ssl(srvkey_pem, srvcert_pem)
        ca = os.path.join(self.tempdir, os.path.basename(cacert_pem))
        shutil.copy(cacert_pem, ca)
        testlib.recursive_rm(tmpdir)

        cmdline = 'openssl s_client -tls1 -connect localhost:443 -CAfile %s' % ca

        child = pexpect.spawn(cmdline)
        time.sleep(0.2)

        # OpenSSL in 14.04 is now built with compression completely
        # disabled, so this should remain disabled even if we tried turning it on
        if self.lsb_release['Release'] >= 14.04:
            search = 'Compression: NONE'
        else:
            search = 'Compression: zlib compression'

        succeeded = False
        try:
            child.expect('.*' + search + '.*', timeout=2)
            succeeded = True
        except:
            succeeded = False

        time.sleep(0.2)
        child.kill(0)

        result = "Could not find appropriate compression setting"
        self.assertTrue(succeeded, result)

    def test_php(self):
        '''Test php'''
        if not os.path.exists(self.php5_mod):
            self._skipped("libapache2-mod-php5 not installed")
            return True

        self._enable_mod("php5")
        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url("http://localhost/" + \
                       os.path.basename(self.php_page), test_str)

    def test_mod_deflate_input(self):
        '''Test mod_deflate input compression'''
        if not os.path.exists(self.php5_mod):
            self._skipped("libapache2-mod-php5 not installed")
            return True

        # Enable the required modules
        modules = ["php5", "deflate"]

        self._enable_mods(modules)

        # create the conffile entry
        contents = '''
SetInputFilter DEFLATE
'''
        testlib.create_fill(self.testlib_conf, contents)
        self._reload()

        test_str = testlib_httpd.create_php_page(self.php_page,
                                                 'echo $_POST["name"];')

        uncompressed = ("keya=valuea&keyb=valueb&keyc=valuec&"
                        "keyd=valued&keye=valuee&name=coolname&blah=yessir")

        # gzip -n testdata.txt
        compressed = ("\037\213\010\000\000\000\000\000\000\003\045\306\321\011\300\060"
                      "\010\005\300\377\016\342\026\016\243\346\101\112\154\003\011\055"
                      "\270\175\020\357\353\006\102\370\027\377\040\064\020\132\327\274"
                      "\325\055\337\352\055\217\072\350\225\007\154\163\172\206\324\245"
                      "\163\140\357\173\135\007\276\010\316\164\126\000\000\000")

        # First test with uncompressed data
        request = ("POST /test.php HTTP/1.1\nHost: localhost\n"
                   "Content-Type: application/x-www-form-urlencoded\n"
                   "Content-Length: %s\n"
                   "\n%s\n\n" % (len(uncompressed), uncompressed))

        self._test_raw(request, 'coolname')

        # Now test with compressed data
        request = ("POST /test.php HTTP/1.1\nHost: localhost\n"
                   "Content-Type: application/x-www-form-urlencoded\n"
                   "Content-Length: %s\n"
                   "Content-Encoding: gzip\n"
                   "\n%s\n\n" % (len(compressed), compressed))

        self._test_raw(request, 'coolname')

    def test_cve_2007_6203(self):
        '''Test CVE-2007-6203'''
        request = "<XSSTEST> / HTTP/1.1\nHost: localhost\nConnection: close\nContent-length: 0\nContent-length: 0\n\n"
        self._test_raw(request, '<XSSTEST>', invert=True)

    def test_mod_status(self):
        '''Test mod_status'''

        # Enable the required modules
        modules = ["status"]

        self._enable_mods(modules)

        self._test_url("http://localhost/server-status", "Apache Server Status")

    def test_mod_cgid(self):
        '''Test mod_cgid'''

        # Enable the required modules
        modules = ["cgid"]

        self._enable_mods(modules)

        # create the conffile entry
        contents = '''
ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
<Directory "/usr/lib/cgi-bin">
	AllowOverride None
	Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
	Require all granted
</Directory>
'''

        if self.lsb_release['Release'] >= 14.04:
            testlib.create_fill(self.testlib_conf, contents)
            self._reload()

        test_str = testlib_httpd.create_perl_script(self.cgi_page)
        self._test_url("http://localhost/cgi-bin/" + \
                       os.path.basename(self.cgi_page), test_str)


    def test_cve_2007_6420(self):
        '''Test CVE-2007-6420'''

        if self.lsb_release['Release'] == 6.06:
            self._skipped("Dapper doesn't have mod_proxy_balancer")
            return True

        # Enable the required modules
        if self.lsb_release['Release'] >= 13.10:
            modules = ["proxy_balancer", "lbmethod_byrequests"]
        else:
            modules = ["proxy_balancer", "status"]

        self._enable_mods(modules)

        # create the conffile entry
        contents = '''
<Location /balancer-manager>
SetHandler balancer-manager
Order Deny,Allow
Allow from all
</Location>

<Proxy balancer://mycluster>
BalancerMember http://127.0.0.1:80
</Proxy>
ProxyPass /test balancer://mycluster/
'''
        testlib.create_fill(self.testlib_conf, contents)
        self._reload()

        # See if we have a nonce
        request = "GET /balancer-manager HTTP/1.1\nHost: localhost\nConnection: close\n\n"
        self._test_raw(request, 'nonce', limit=4096)

    def test_cve_2008_2168(self):
        '''Test CVE-2008-2168'''

        # Disable the default charset
        testlib.config_replace(self.charset, "#disabled")

        # Enable the info module
        self._enable_mod("info")

        # create the conffile entry
        contents = '''
<Location /server-info>
SetHandler server-info
Order deny,allow
Allow from all
</Location>
'''
        testlib.create_fill(self.testlib_conf, contents)
        self._reload()

        # Now see if we have a charset
        request = "GET /server-info HTTP/1.1\nHost: localhost\nConnection: close\n\n"
        self._test_raw(request, 'ISO-8859-1')

    def test_cve_2008_2939(self):
        '''Test CVE-2008-2939'''

        # Enable proxying
        testlib.config_replace(self.proxy_conf, "", append=True)
        subprocess.call(['sed', '-i', 's/ProxyRequests Off/ProxyRequests On/', self.proxy_conf])
        subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])

        # Enable the ftp proxy module
        self._enable_mods(["proxy", "proxy_ftp"])

        # We need a working ftp server for this. Using ftp.ubuntu.com for now.
        request = "GET ftp://ftp.ubuntu.com/*<XSSTEST> HTTP/1.0\n\n"
        self._test_raw(request, '<XSSTEST>', invert=True)
        self._test_raw(request, '&lt;XSSTEST&gt;')

    def test_cve_2009_1890(self):
        '''Test CVE-2009-1890'''

        # Basically does: http://svn.apache.org/viewvc?view=rev&revision=790589

        # Enable proxying
        testlib.config_replace(self.proxy_conf, "", append=True)

        if self.lsb_release['Release'] == 6.06:
            new_url = "http:\/\/localhost\/apache2-default\/"
        else:
            new_url = "http:\/\/localhost\/"

        if self.lsb_release['Release'] < 10.10:
            subprocess.call(['sed', '-i', "s/ProxyVia On/ProxyPass \/foo " + new_url +
                                          "\\nProxyPassReverse \/foo " + new_url +"/", self.proxy_conf])

            subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])
        else:
            subprocess.call(['sed', '-i', "s/#ProxyVia Off/<Proxy *>" +
                                          "\\nAddDefaultCharset off" +
                                          "\\nOrder deny,allow" +
                                          "\\nAllow from all" +
                                          "\\n<\/Proxy>" +
                                          "\\nProxyPass \/foo " + new_url +
                                          "\\nProxyPassReverse \/foo " + new_url +"/", self.proxy_conf])

        # Enable the http proxy module
        self._enable_mods(["proxy", "proxy_http"])

        result=''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        request = "POST /foo/index.html HTTP/1.0\r\nContent-Length: 0100000\r\n\r\n"
        s.send(request)
        data = 'x' * 50000
        s.send(data)
        time.sleep(1)
        s.send(data)
        time.sleep(1)
        try:
            result = s.recv(1024, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()

        self._word_find(result, "HTTP/1.1 200 OK")

    def test_basic_rewrite(self):
        '''Test basic rewrite functionality'''

        # Enable proxying
        testlib.config_replace(self.default_vhost, "", append=True)
        testlib.config_replace(self.proxy_conf, "", append=True)

        url = "http://localhost@archive.ubuntu.com/ubuntu/test.png"

        subprocess.call(['sed', '-i', 's#^</VirtualHost>#RewriteEngine on' +
                                      '\\nRewriteRule (.*)test\.(ico|jpg|gif|png) http://localhost$1ubuntu.$2 [P]' +
                                      '\\n</VirtualHost>#', self.default_vhost])
        if self.lsb_release['Release'] < 10.10:
            subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])

        # Enable the http proxy module
        self._enable_mods(["rewrite", "proxy", "proxy_http"])

        # test that the proxy rewrite functions by connecting to a port
        # that doesn't have a service on it; this should return a 404
        request = "GET /test.png HTTP/1.0\r\n\r\n"
        self._test_raw(request, 'HTTP/1.1 404 Not Found')
        self._test_raw(request, 'URL /ubuntu.png')

    def test_cve_2011_3368(self):
        '''Test CVE-2011-3368'''

        # Enable proxying
        testlib.config_replace(self.default_vhost, "", append=True)
        testlib.config_replace(self.proxy_conf, "", append=True)

        url = "http://localhost@archive.ubuntu.com/ubuntu/test.png"

        subprocess.call(['sed', '-i', 's#^</VirtualHost>#RewriteEngine on' +
                                      '\\nRewriteRule (.*)test\.(ico|jpg|gif|png) http://localhost$1ubuntu.$2 [P]' +
                                      '\\n</VirtualHost>#', self.default_vhost])
        if self.lsb_release['Release'] < 10.10:
            subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])

        # Enable the http proxy module
        self._enable_mods(["rewrite", "proxy", "proxy_http"])

        # attempt to get a file that does not exist off of
        # archive.ubuntu.com; apache should return a 400 and not the 404
        # from archive.ubuntu.com
        request = "GET @archive.ubuntu.com/ubuntu/test.png HTTP/1.0\r\n\r\n"
        self._test_raw(request, 'HTTP/1.1 400 Bad Request')
        self._test_raw(request, 'archive.ubuntu.com', invert=True)

    def test_cve_2011_3368_proto_09(self):
        '''Test CVE-2011-3368 w/http protocol 0.9'''

        # Enable proxying
        testlib.config_replace(self.default_vhost, "", append=True)
        testlib.config_replace(self.proxy_conf, "", append=True)

        url = "http://localhost@archive.ubuntu.com/ubuntu/test.png"

        subprocess.call(['sed', '-i', 's#^</VirtualHost>#RewriteEngine on' +
                                      '\\nRewriteRule (.*)test\.(ico|jpg|gif|png) http://localhost$1ubuntu.$2 [P]' +
                                      '\\n</VirtualHost>#', self.default_vhost])
        if self.lsb_release['Release'] < 10.10:
            subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])

        # Enable the http proxy module
        self._enable_mods(["rewrite", "proxy", "proxy_http"])

        # do the same but check for http protocol 0.9
        request = "GET @archive.ubuntu.com/ubuntu/test.png\r\n\r\n"
        self._test_raw(request, '400 Bad Request')
        self._test_raw(request, 'archive.ubuntu.com', invert=True)

    def test_cve_2011_4317(self):
        '''Test CVE-2011-4317'''

        # Enable proxying
        testlib.config_replace(self.default_vhost, "", append=True)
        testlib.config_replace(self.proxy_conf, "", append=True)

        url = "http://localhost@archive.ubuntu.com/ubuntu/test.png"

        subprocess.call(['sed', '-i', 's#^</VirtualHost>#RewriteEngine on' +
                                      '\\nRewriteRule (.*)test\.(ico|jpg|gif|png) http://localhost$1ubuntu.$2 [P]' +
                                      '\\n</VirtualHost>#', self.default_vhost])
        if self.lsb_release['Release'] < 10.10:
            subprocess.call(['sed', '-i', 's/Deny from all/Allow from all/', self.proxy_conf])

        # Enable the http proxy module
        self._enable_mods(["rewrite", "proxy", "proxy_http"])

        # attempt to get a file that does not exist off of
        # archive.ubuntu.com; apache should return a 400 and not the 404
        # from archive.ubuntu.com
        request = "GET blahblah:@archive.ubuntu.com/ubuntu/test.png HTTP/1.0\r\n\r\n"
        self._test_raw(request, 'HTTP/1.1 400 Bad Request')
        self._test_raw(request, 'archive.ubuntu.com', invert=True)

    def test_cve_2011_0419(self):
        '''Test CVE-2011-0419'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("PoC doesn't work on Quantal and newer")

        # based on demo script by Maksymilian Arciemowicz
        testdir = "/var/www/cve-2011-0419"
        if not os.path.exists(testdir):
            os.mkdir(testdir, 0755)
        testfile = "foo" + 'a' * 32
        test_str = testlib_httpd.create_html_page(testdir + "/" + testfile)

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        request = "GET /cve-2011-0419/ HTTP/1.0\r\n\r\n"
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()
        self._word_find(result, testfile)

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        request = "GET /cve-2011-0419/?P=" + ('*?' * 512) + " HTTP/1.0\r\n\r\n"
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()
        self._word_find(result, "Parent Directory")

        shutil.rmtree(testdir)

    def test_cve_2011_3192(self):
        '''Test CVE-2011-3192'''

        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Ubuntu 13.10+ not affected")

        request = "HEAD / HTTP/1.1\r\nHost: localhost\r\nRange:bytes=1-15,10-35,8-9,14-22,0-5,23-\r\nConnection: close\r\n\r\n"

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()

        # specifically, we don't want to see "HTTP/1.1 206 Partial Content"
        self._word_find(result, "HTTP/1.1 200 OK")

    def test_cve_2011_3192_gzip(self):
        '''Test CVE-2011-3192 (gzip)'''

        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Ubuntu 13.10+ not affected")

        request = "HEAD / HTTP/1.1\r\nHost: localhost\r\nRange:bytes=1-15,10-35,8-9,14-22,0-5,23-\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()

        # specifically, we don't want to see "HTTP/1.1 206 Partial Content"
        self._word_find(result, "HTTP/1.1 200 OK")

    def test_cve_2011_3192_request_range(self):
        '''Test CVE-2011-3192 (Request-Range)'''

        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Ubuntu 13.10+ not affected")

        request = "HEAD / HTTP/1.1\r\nHost: localhost\r\nRequest-Range:bytes=1-15,10-35,8-9,14-22,0-5,23-\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()

        # specifically, we don't want to see "HTTP/1.1 206 Partial Content"
        self._word_find(result, "HTTP/1.1 200 OK")

    def test_cve_2011_3192_regression_1(self):
        '''Test CVE-2011-3192 regression 1

        Test for Range:bytes=0- returning HTTP/1.1 206 Partial Content
        as described in
        http://marc.info/?l=apache-httpd-dev&m=131482445624089&w=2 and
        http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=639825'''

        request = "HEAD / HTTP/1.1\r\nHost: %s\r\nRange:bytes=0-\r\nAccept-Encoding: %gzip\r\nConnection: close\r\n\r\n"

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()

        self._word_find(result, "HTTP/1.1 206 Partial Content")

    def test_cve_2011_3192_regression_2(self):
        '''Test CVE-2011-3192 regression 2

        Test Range:bytes=x-y where x -> y doesn't cover any of the
        valid byte ranges returns "HTTP/1.1 416 Requested Range Not
        Satisfiable" as described in
        http://marc.info/?l=apache-httpd-dev&m=131482610125970&w=2 and
        http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=639825'''

        request = "HEAD / HTTP/1.1\r\nHost: %s\r\nRange:bytes=500000-500005\r\nAccept-Encoding: %gzip\r\nConnection: close\r\n\r\n"

        result = ''

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 80))
        s.send(request)
        time.sleep(1)
        try:
            result = s.recv(4096 * 4, socket.MSG_DONTWAIT)
        except:
            pass
        s.close()

        self._word_find(result, "HTTP/1.1 416 Requested Range Not Satisfiable")

    def test_mod_dav(self):
        '''Test mod_dav'''

        # create the dav lovk
        dav_lock = os.path.join(self.tempdir, 'lock')
        dav_dir = os.path.join(self.tempdir, 'dav')
        dav_user = "foo"
        dav_password = "bar"
        dav_mnturl = "http://localhost/dav"
        dav_topurl = "http://" + dav_user + ":" + dav_password + "@localhost/dav"
        self.mountpoint = os.path.join(self.tempdir, 'mnt')
        test_str = "Dude!"
        htpasswd = os.path.join(self.tempdir, 'htpasswd.dav')
        os.mkdir(dav_dir)
        os.mkdir(dav_lock)
        os.mkdir(self.mountpoint)

        testlib.config_replace("/etc/davfs2/secrets", "http://localhost/dav " + dav_user + " " + dav_password + "\n", append=True)
        os.chmod("/etc/davfs2/secrets", 0600)

        # adjust permissions
        subprocess.call(['chown', 'www-data:www-data', dav_dir])
        os.chmod(dav_dir, 0775)
        subprocess.call(['chown', 'www-data:www-data', dav_lock])
        os.chmod(dav_lock, 0775)
        os.chmod(self.tempdir, 0755)
        subprocess.call(['chgrp', 'www-data', self.tempdir])

        self._enable_mods(["dav", "dav_fs"])
        if self.lsb_release['Release'] >= 12.04:
            self._enable_mods(["auth_basic"])
        if self.lsb_release['Release'] >= 13.10:
            self._enable_mods(["authn_core"])


        # create the repository
        localpath = os.path.join(dav_dir, "testlib.txt")
        testlib.create_fill(localpath, test_str)
        self._add_basic_auth_user(dav_user, dav_password, htpasswd)
        testlib.config_replace(self.default_vhost, "", append=True)

        subprocess.call(['sed', '-i', 's#^</VirtualHost>#DAVLockDB ' + os.path.join(dav_lock, "DAVLock") + '\\nAlias /dav/ "' + dav_dir + '/"\\n<Location /dav>\\nOrder Allow,Deny\\nAllow from all\\nDAV on\\nAuthType Basic\\nAuthName "WebDAV Repository"\\nAuthUserFile ' + htpasswd + '\\n<Limit PUT MPUT POST DELETE PROPFIND PROPPATCH MKCOL COPY MOVE LOCK UNLOCK>\\nRequire valid-user\\n</Limit>\\n</Location>\\n</VirtualHost>#', self.default_vhost])

        self._restart()

        # now the real tests (DAV commands are in parentheses)

        # are we serving our file over non-dav (GET)
        self._test_url(dav_topurl + "/testlib.txt", test_str)
        localpath = os.path.join(self.mountpoint, "testlib.txt")

        # mount dav share (OPTIONS, PROPFIND)
        subprocess.call(['mount', '-t', 'davfs', dav_mnturl, self.mountpoint])
        self.assertTrue(os.path.exists(localpath), "Could not find '%s'" % (localpath))

        # create file and see if we can read it via url
        newlocalpath = os.path.join(self.mountpoint, "test_davfs2.txt")
        # use 'cp' here rather than shutil.copy cause davfs2 doesn't play well
        # with python (GET, HEAD, LOCK, PUT, UNLOCK)
        (rc, report) = testlib.cmd(['cp', '-f', localpath, newlocalpath])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        # (GET)
        contents = file(newlocalpath).read()
        self._word_find(test_str, contents)

        # for some reason, when doing an fs copy, it doesn't show up right away
        # in apache
        count = 0
        while count < 10:
            try:
                self._test_url(dav_topurl + "/test_davfs2.txt", test_str)
                break
            except:
                count += 1
                time.sleep(2)
            if count >= 10:
                self._test_url(dav_topurl + "/test_davfs2.txt", test_str)

        localpath = newlocalpath

        # move file and see if we can read it via url
        newlocalpath = os.path.join(self.mountpoint, "test_mkdir", "moved.txt")
        # (PROPFIND, MKCOL)
        os.mkdir(os.path.dirname(newlocalpath))
        # (MOVE, HEAD)
        os.rename(localpath, newlocalpath)
        self._test_url(dav_topurl + "/test_mkdir/moved.txt", test_str)
        self.assertTrue(os.path.exists(newlocalpath), "Could not find '%s'" % (newlocalpath))
        localpath = newlocalpath

        # delete file and see if we cannot read it via url (DELETE)
        os.unlink(localpath)

        search = "Not Found"
        if self.lsb_release['Release'] <= 6.10 or self.lsb_release['Release'] >= 9.10:
            search = "not found"
        self._test_url(dav_topurl + "/test_mkdir/moved.txt", search)
        self._test_url(dav_topurl + "/test_davfs2.txt", search)

        # delete the directory (DELETE)
        (rc, report) = testlib.cmd(['rmdir', os.path.dirname(localpath)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_mod_dav_svn(self):
        '''Test mod_dav_svn'''

        # create the svn repo
        svn_dir = os.path.join(self.tempdir, 'svn')
        dav_lock = os.path.join(self.tempdir, 'lock')
        co_dir = os.path.join(self.tempdir, 'co')
        svn_repo = os.path.join(svn_dir, 'example')
        svn_user = "foo"
        svn_password = "bar"
        svn_topurl = "http://" + svn_user + ":" + svn_password + "@localhost/svn/example"
        htpasswd = os.path.join(self.tempdir, 'htpasswd.svn')
        os.mkdir(svn_dir)
        os.mkdir(dav_lock)
        os.mkdir(co_dir)

        # adjust permissions
        subprocess.call(['chown', 'www-data:www-data', svn_dir])
        os.chmod(svn_dir, 0770)
        subprocess.call(['chown', 'www-data:www-data', dav_lock])
        os.chmod(dav_lock, 0775)
        subprocess.call(['chown', 'www-data:www-data', co_dir])
        os.chmod(co_dir, 0770)
        os.chmod(self.tempdir, 0750)
        subprocess.call(['chgrp', 'www-data', self.tempdir])

        self._enable_mods(["dav", "dav_svn", "dav_fs"])
        if self.lsb_release['Release'] >= 12.04:
            self._enable_mods(["auth_basic"])
        if self.lsb_release['Release'] >= 13.10:
            self._enable_mods(["authn_core"])

        # adjust to old behavior
        if self.lsb_release['Release'] >= 9.10:
            testlib.config_replace("/etc/subversion/servers", "store-plaintext-passwords = yes", append=True)

        # create the repository
        (rc, report) = testlib.cmd(['sudo', '-u', 'www-data', 'svnadmin', '--config-dir', self.tempdir, 'create', svn_repo])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # import some stuff
        (rc, report) = testlib.cmd(['sudo', '-u', 'www-data', 'svn', '--config-dir', self.tempdir, 'import', '/etc/apache2', 'file://' + svn_repo + '/testlib', '-m', '"initial commit"'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._add_basic_auth_user(svn_user, svn_password, htpasswd)

        testlib.config_replace(self.default_vhost, "", append=True)
        subprocess.call(['sed', '-i', 's#^</VirtualHost>#DAVLockDB ' + os.path.join(dav_lock, "DAVLock") + '\\n<Location /svn>\\nDAV svn\\nSVNParentPath ' + svn_dir + '\\nAuthType Basic\\nAuthName "Subversion Repository"\\nAuthUserFile ' + htpasswd + '\\nRequire valid-user\\n</Location>\\n</VirtualHost>#', self.default_vhost])

        self._restart()
        if self.lsb_release['Release'] >= 12.10:
            test_file = "apache2.conf"
        else:
            test_file = "httpd.conf"
        self._test_url(svn_topurl + "/testlib", test_file)

        # do some checkouts, etc
        os.chdir(co_dir)
        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'svn', 'co', '--username', svn_user, '--password', svn_password, 'http://localhost/svn/example'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.chdir(os.path.join(co_dir, "example"))
        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'cp', '/etc/passwd', os.path.join(co_dir, 'example')])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'svn', 'add', 'passwd'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'svn', 'diff'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue('root' in report, "Could not find '%s' in %s" % ('root', report))

        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'svn', 'ci', '--username', svn_user, '--password', svn_password, '-m', 'added passwd'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # try to diff to nonexistent version
        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'svn', 'diff', '-r', '1:3', '--username', svn_user, '--password', svn_password])
        unexpected = 0
        result = 'Got unexpected exit code %d\n' % (unexpected)
        self.assertFalse(rc == unexpected, result + report)

        (rc, report) = testlib.cmd(['sudo', '-H', '-u', 'www-data', 'svn', 'diff', '-r', '1:2', '--username', svn_user, '--password', svn_password])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue('root' in report, "Could not find '%s' in %s" % ('root', report))

    def disabled_test_mod_include(self):
        '''Test mod_include'''

        # This test is disabled at it takes an insanely long time to run

        # Options, AllowOverride, .htaccess, search_str, invert_match
        # search_str ssi_exec (eg pwd: /tmp/...) means that 'pwd' was executed
        # in the shtml and search_str ssi_noexec (ie pwd: [an error occurred)
        # means that 'pwd' was not allowed to execute. Internal Server Error is
        # an expected invalid combiniation. Tests based on:
        # https://bugzilla.redhat.com/attachment.cgi?id=341203
        # http://people.apache.org/~jorton/ssi-exec/t3-jorton-v1.html. Note
        # that there are 3 changes to the table due to a mod_perl
        # regression. These tests have been noted.
        server_error = "Internal Server Error"
        if self.lsb_release['Release'] == 9.10:
            server_error = "Server error"
        ssi_noexec = "pwd: ["
        ssi_exec = "pwd: /"
        no_ssi = "ssi: ssi_end"
        has_ssi = "ssi:["
        tests = (
                  ('None', 'All', '+Includes', ssi_exec, False),
                  ('None', 'All', '+IncludesNoExec', ssi_noexec, False),
                  ('None', 'All', 'Includes', ssi_exec, False),
                  ('None', 'All', 'IncludesNoExec', ssi_noexec, False),
                  ('None', 'All', '-Includes', no_ssi, False),
                  ('None', 'All', '-IncludesNoExec', no_ssi, False),
                  ('None', 'All', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('None', 'All', '+Includes -IncludesNoExec', no_ssi, False),
                  ('None', 'All', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('None', 'All', '+IncludesNoExec -Includes', no_ssi, False),

                  ('None', 'None', '+Includes', no_ssi, False),
                  ('None', 'None', '+IncludesNoExec', no_ssi, False),
                  ('None', 'None', 'Includes', no_ssi, False),
                  ('None', 'None', 'IncludesNoExec', no_ssi, False),
                  ('None', 'None', '-Includes', no_ssi, False),
                  ('None', 'None', '-IncludesNoExec', no_ssi, False),
                  ('None', 'None', '-Includes +IncludesNoExec', no_ssi, False),
                  ('None', 'None', '+Includes -IncludesNoExec', no_ssi, False),
                  ('None', 'None', '-IncludesNoExec +Includes', no_ssi, False),
                  ('None', 'None', '+IncludesNoExec -Includes', no_ssi, False),

                  ('IncludesNoExec', 'All', '+Includes', ssi_exec, False),
                  ('IncludesNoExec', 'All', '+IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'All', 'Includes', ssi_exec, False),
                  ('IncludesNoExec', 'All', 'IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'All', '-Includes', no_ssi, False),
                  ('IncludesNoExec', 'All', '-IncludesNoExec', no_ssi, False),
                  ('IncludesNoExec', 'All', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'All', '+Includes -IncludesNoExec', no_ssi, False),
                  ('IncludesNoExec', 'All', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('IncludesNoExec', 'All', '+IncludesNoExec -Includes', no_ssi, False),

                  ('IncludesNoExec', 'None', '+Includes', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '+IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'None', 'Includes', ssi_noexec, False),
                  ('IncludesNoExec', 'None', 'IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '-Includes', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '-IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '+Includes -IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '-IncludesNoExec +Includes', ssi_noexec, False),
                  ('IncludesNoExec', 'None', '+IncludesNoExec -Includes', ssi_noexec, False),

                  ('Includes', 'All', '+Includes', ssi_exec, False),
                  ('Includes', 'All', '+IncludesNoExec', ssi_noexec, False), # t3-jorton-v1.html has ssi_exec
                  ('Includes', 'All', 'Includes', ssi_exec, False),
                  ('Includes', 'All', 'IncludesNoExec', ssi_noexec, False),
                  ('Includes', 'All', '-Includes', no_ssi, False),
                  ('Includes', 'All', '-IncludesNoExec', no_ssi, False),
                  ('Includes', 'All', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('Includes', 'All', '+Includes -IncludesNoExec', no_ssi, False),
                  ('Includes', 'All', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('Includes', 'All', '+IncludesNoExec -Includes', no_ssi, False),

                  ('Includes', 'None', '+Includes', ssi_exec, False),
                  ('Includes', 'None', '+IncludesNoExec', ssi_exec, False),
                  ('Includes', 'None', 'Includes', ssi_exec, False),
                  ('Includes', 'None', 'IncludesNoExec', ssi_exec, False),
                  ('Includes', 'None', '-Includes', ssi_exec, False),
                  ('Includes', 'None', '-IncludesNoExec', ssi_exec, False),
                  ('Includes', 'None', '-Includes +IncludesNoExec', ssi_exec, False),
                  ('Includes', 'None', '+Includes -IncludesNoExec', ssi_exec, False),
                  ('Includes', 'None', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('Includes', 'None', '+IncludesNoExec -Includes', ssi_exec, False),
                )

        if self.lsb_release['Release'] > 6.10:
	    # Apache 2.2 also has per-Option AllowOverrides. Assumes patches
            # for CVE-2009-1195 are applied.
            per_option_tests = (
                  ('None', 'Options=IncludesNoExec', '+Includes', server_error, False), # CVE-2009-1195
                  ('None', 'Options=IncludesNoExec', '+IncludesNoExec', ssi_noexec, False),
                  ('None', 'Options=IncludesNoExec', 'Includes', server_error, False),
                  ('None', 'Options=IncludesNoExec', 'IncludesNoExec', ssi_noexec, False),
                  ('None', 'Options=IncludesNoExec', '-Includes', server_error, False),
                  ('None', 'Options=IncludesNoExec', '-IncludesNoExec', no_ssi, False),
                  ('None', 'Options=IncludesNoExec', '-Includes +IncludesNoExec', server_error, False),
                  ('None', 'Options=IncludesNoExec', '+Includes -IncludesNoExec', server_error, False),
                  ('None', 'Options=IncludesNoExec', '-IncludesNoExec +Includes', server_error, False),
                  ('None', 'Options=IncludesNoExec', '+IncludesNoExec -Includes', server_error, False),

                  ('None', 'Options=Includes', '+Includes', ssi_exec, False),
                  ('None', 'Options=Includes', '+IncludesNoExec', ssi_noexec, False),
                  ('None', 'Options=Includes', 'Includes', ssi_exec, False),
                  ('None', 'Options=Includes', 'IncludesNoExec', ssi_noexec, False),
                  ('None', 'Options=Includes', '-Includes', no_ssi, False),
                  ('None', 'Options=Includes', '-IncludesNoExec', no_ssi, False),
                  ('None', 'Options=Includes', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('None', 'Options=Includes', '+Includes -IncludesNoExec', no_ssi, False),
                  ('None', 'Options=Includes', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('None', 'Options=Includes', '+IncludesNoExec -Includes', no_ssi, False),

                  ('IncludesNoExec', 'Options=IncludesNoExec', '+Includes', server_error, False), # CVE-2009-1195
                  ('IncludesNoExec', 'Options=IncludesNoExec', '+IncludesNoExec', ssi_noexec, False), # CVE-2009-1195
                  ('IncludesNoExec', 'Options=IncludesNoExec', 'Includes', server_error, False), # CVE-2009-1195
                  ('IncludesNoExec', 'Options=IncludesNoExec', 'IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'Options=IncludesNoExec', '-Includes', server_error, False),
                  ('IncludesNoExec', 'Options=IncludesNoExec', '-IncludesNoExec', no_ssi, False),
                  ('IncludesNoExec', 'Options=IncludesNoExec', '-Includes +IncludesNoExec', server_error, False),
                  ('IncludesNoExec', 'Options=IncludesNoExec', '+Includes -IncludesNoExec', server_error, False),
                  ('IncludesNoExec', 'Options=IncludesNoExec', '-IncludesNoExec +Includes', server_error, False),
                  ('IncludesNoExec', 'Options=IncludesNoExec', '+IncludesNoExec -Includes', server_error, False),

                  ('IncludesNoExec', 'Options=Includes', '+Includes', ssi_exec, False),
                  ('IncludesNoExec', 'Options=Includes', '+IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'Options=Includes', 'Includes', ssi_exec, False),
                  ('IncludesNoExec', 'Options=Includes', 'IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'Options=Includes', '-Includes', no_ssi, False),
                  ('IncludesNoExec', 'Options=Includes', '-IncludesNoExec', no_ssi, False),
                  ('IncludesNoExec', 'Options=Includes', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('IncludesNoExec', 'Options=Includes', '+Includes -IncludesNoExec', no_ssi, False),
                  ('IncludesNoExec', 'Options=Includes', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('IncludesNoExec', 'Options=Includes', '+IncludesNoExec -Includes', no_ssi, False),

                  ('Includes', 'Options=IncludesNoExec', '+Includes', server_error, False),
                  ('Includes', 'Options=IncludesNoExec', '+IncludesNoExec', ssi_noexec, False), # t3-jorton-v1.html has ssi_exec
                  ('Includes', 'Options=IncludesNoExec', 'Includes', server_error, False),
                  ('Includes', 'Options=IncludesNoExec', 'IncludesNoExec', ssi_noexec, False),
                  ('Includes', 'Options=IncludesNoExec', '-Includes', server_error, False),
                  ('Includes', 'Options=IncludesNoExec', '-IncludesNoExec', no_ssi, False),
                  ('Includes', 'Options=IncludesNoExec', '-Includes +IncludesNoExec', server_error, False),
                  ('Includes', 'Options=IncludesNoExec', '+Includes -IncludesNoExec', server_error, False),
                  ('Includes', 'Options=IncludesNoExec', '-IncludesNoExec +Includes', server_error, False),
                  ('Includes', 'Options=IncludesNoExec', '+IncludesNoExec -Includes', server_error, False),

                  ('Includes', 'Options=Includes', '+Includes', ssi_exec, False),
                  ('Includes', 'Options=Includes', '+IncludesNoExec', ssi_noexec, False), # t3-jorton-v1.html has ssi_exec
                  ('Includes', 'Options=Includes', 'Includes', ssi_exec, False),
                  ('Includes', 'Options=Includes', 'IncludesNoExec', ssi_noexec, False),
                  ('Includes', 'Options=Includes', '-Includes', no_ssi, False),
                  ('Includes', 'Options=Includes', '-IncludesNoExec', no_ssi, False),
                  ('Includes', 'Options=Includes', '-Includes +IncludesNoExec', ssi_noexec, False),
                  ('Includes', 'Options=Includes', '+Includes -IncludesNoExec', no_ssi, False),
                  ('Includes', 'Options=Includes', '-IncludesNoExec +Includes', ssi_exec, False),
                  ('Includes', 'Options=Includes', '+IncludesNoExec -Includes', no_ssi, False),
                )
            tests += per_option_tests

        self._enable_mod("include")
        if self.lsb_release['Release'] >= 13.10:
            self._enable_mod("cgi")

        os.chmod(self.tempdir, 0755)
        index_shtml = os.path.join(self.tempdir, "index.shtml")
        test_shtml = os.path.join(self.tempdir, "test.shtml")
        htaccess_file = os.path.join(self.tempdir, ".htaccess")
        url = "http://localhost/test/index.shtml"
        vulnerable = False
        contents = '''<html>
<body>
ssi:<!--#flastmod file="front.shtml" --> ssi_end
<!--#include virtual="/test/test.shtml" -->
</body></html>
'''
        testlib.create_fill(index_shtml, contents)

        contents = '''<html>
<body>
<p>start</p>
<pre>
pwd: <!--#exec cmd="pwd" -->
</pre>
<p>end</p>
</body>
</html>
'''
        testlib.create_fill(test_shtml, contents)

        print ""
        print "  # Options, AllowOverride, htaccess"
        failures = ""
        for options, allowoverride, htaccess, search, invert in tests:
            report = "  '%s', '%s', '%s'" % (options, allowoverride, htaccess)
            print report + " ...",
            sys.stdout.flush()

            ok = True
            testlib.config_restore(self.default_vhost)
            if os.path.exists(htaccess_file):
                os.unlink(htaccess_file)

            testlib.create_fill(htaccess_file, "Options %s\n" % htaccess)
            testlib.config_replace(self.default_vhost, "", append=True)
            if self.lsb_release['Release'] >= 13.10:
                subprocess.call(['sed', '-i', 's#^</VirtualHost>#\\nAlias /test/ "' + self.tempdir + '/"\\n<Directory "' + self.tempdir + '">\\nOptions ' + options + '\\nAllowOverride ' + allowoverride + '\\nRequire all granted\\n</Directory>\\n</VirtualHost>#', self.default_vhost])
            else:
                subprocess.call(['sed', '-i', 's#^</VirtualHost>#\\nAlias /test/ "' + self.tempdir + '/"\\n<Directory "' + self.tempdir + '">\\nOptions ' + options + '\\nAllowOverride ' + allowoverride + '\\n</Directory>\\n</VirtualHost>#', self.default_vhost])
            self._restart()

            page = self._get_page(url)

            # make sure no problems with the configuration
            if search != server_error:
                self._word_find(page, server_error, True)

            try:
                self._word_find(page, search, invert)
                ok = True
            except:
                ok = False
                failures += "FAILURE:\n%s" % (report)
                if invert:
                    failures += " -- found '%s' in:\n" % (search)
                else:
                    failures += " -- could not find '%s' in:\n" % (search)
                failures += "%s\n\n" % (page)

            if ok:
                print "ok"
            else:
                print "FAIL"

        self.assertTrue(failures == "", "Failures:\n%s" % (failures))

class HTPasswdTest(testlib.TestlibCase):
    '''Test basic htpasswd functionality'''

    def setUp(self):
        '''Setup mechanisms'''

    def tearDown(self):
        '''Shutdown methods'''

    def test_htpasswd_des(self):
        '''Test htpasswd to ensure crypt returns sane des results'''

        rc, report = testlib.cmd(["htpasswd", "-nbd", "ubuntu", "password"])
        self.assertEquals(0, rc, report)

        # htpasswd uses a randomly generated salt; parse it out and
        # compare output to openssl passwd
        output = report.splitlines()[0]
        # salt is first two characters
        salt = output.split(':')[1][0:2]
        rc, report = testlib.cmd(["openssl", "passwd", "-salt", salt, "password"])
        self.assertEquals(0, rc, report)

        self.assertEquals(output.split(':')[1], report.splitlines()[0], output + " " + report)

    def test_htpasswd_md5(self):
        '''Test htpasswd to ensure crypt returns sane md5 results'''

        rc, report = testlib.cmd(["htpasswd", "-nbm", "ubuntu", "password"])
        self.assertEquals(0, rc, report)

        # htpasswd uses a randomly generated salt; parse it out and
        # compare output to openssl passwd
        output = report.splitlines()[0]
        # format is $apr1$salt$ ; pull salt out
        salt = output.split('$')[2]
        rc, report = testlib.cmd(["openssl", "passwd", "-apr1", "-salt", salt, "password"])
        self.assertEquals(0, rc, report)

        self.assertEquals(output.split(':')[1], report.splitlines()[0], output + " " + report)

    def test_htpasswd_sha(self):
        '''Test htpasswd to ensure crypt returns sane sha results'''

        rc, report = testlib.cmd(["htpasswd", "-nbs", "ubuntu", "password"])
        self.assertEquals(0, rc, report)
        self.assertEquals('ubuntu:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=', report.splitlines()[0], report)


if __name__ == '__main__':
    testlib.require_root()
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(HTPasswdTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
