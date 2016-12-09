#!/usr/bin/python
#
#    testlib_httpd.py quality assurance test script
#    Copyright (C) 2008-2013 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
#    along with this program.  If not, see <httpd://www.gnu.org/licenses/>.
#

import subprocess
import os
import sys
import testlib
import time
import socket
import shutil
import cookielib
import urllib2
import re
import base64

class HttpdCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self, clearlogs = False):
        '''Setup'''
        self.release = self.lsb_release['Codename']

        if self.lsb_release['Release'] >= 14.04:
            self.document_root = "/var/www/html"
        else:
            self.document_root = "/var/www"

        self.html_page = os.path.join(self.document_root, "test.html")
        self.php_page = os.path.join(self.document_root, "test.php")

        self.cgi_page = "/usr/lib/cgi-bin/test-cgi.pl"
        self.apache2_default = "/etc/default/apache2"
        self.ssl_key = "/etc/ssl/private/server.key"
        self.ssl_crt = "/etc/ssl/certs/server.crt"
        self.ssl_site = "/etc/apache2/sites-enabled/999-testlib.conf"
        self.ports_file = "/etc/apache2/ports.conf"
        self.access_log = "/var/log/apache2/access.log"
        self.error_log = "/var/log/apache2/error.log"
        if not hasattr(self, 'initscript'):
            self._set_initscript("/etc/init.d/apache2")

        # Dapper's apache2 is disabled by default
        if self.lsb_release['Release'] == 6.06:
            testlib.config_replace(self.apache2_default, "", append=True)
            subprocess.call(['sed', '-i', 's/NO_START=1/NO_START=0/', self.apache2_default])

        self.enabled_mods = []
        self.disabled_mods = []

        self._stop()
        if clearlogs == True:
            self._clearlogs()
        self._start()

    def _set_initscript(self, initscript, initdaemon='sysvinit'):
        self.initscript = initscript
        self.initdaemon = initdaemon

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self._stop()
        time.sleep(2)
        if os.path.exists(self.html_page):
            os.unlink(self.html_page)
        if os.path.exists(self.php_page):
            os.unlink(self.php_page)
        if os.path.exists(self.cgi_page):
            os.unlink(self.cgi_page)
        if os.path.exists(self.ssl_key):
            os.unlink(self.ssl_key)
        if os.path.exists(self.ssl_crt):
            os.unlink(self.ssl_crt)
        if os.path.exists(self.ssl_site):
            os.unlink(self.ssl_site)

        self._disable_mods(self.enabled_mods, keep_state=False, restart=False)
        self._enable_mods(self.disabled_mods, keep_state=False)

        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.apache2_default)

    def _start(self):
        '''Start httpd'''
        #print self.initscript,"start"
        expected = 0
        if self.initdaemon == 'upstart':
            rc, report = testlib.cmd(['start', self.initscript])
        else:
            rc, report = testlib.cmd([self.initscript, 'start'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(2)

    def _stop(self):
        '''Stop httpd'''
        #print self.initscript,"stop"
        expected = 0
        if self.initdaemon == 'upstart':
            rc, report = testlib.cmd(['stop', self.initscript])
            if rc != expected and 'Unknown instance' in report:
                rc = 0
        else:
            rc, report = testlib.cmd([self.initscript, 'stop'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _clearlogs(self):
        '''Clear httpd logs'''
        if os.path.exists(self.access_log):
            os.unlink(self.access_log)
        if os.path.exists(self.error_log):
            os.unlink(self.error_log)

    def _mod_enabled(self, mod):
        '''See if a mod is enabled or not'''

        rc, report = testlib.cmd(['a2query', '-m', mod])
        return (rc == 0)

    def __disable_mod(self, mod, keep_state=True):
        if not os.path.exists(os.path.join("/etc/apache2/mods-available", mod + \
                                       ".load")):
            return
        if not os.path.exists("/usr/sbin/a2dismod"):
            return

        if self._mod_enabled(mod) == True:
            if keep_state:
                self.disabled_mods += [mod]

            # We have to pass --force or other modules enabled by
            # dependency will cause it to fail
            rc, report = testlib.cmd(['a2dismod', '-f', mod])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def _disable_mod(self, mod, keep_state=True, restart=True):
        self.__disable_mod(mod, keep_state)
        if restart:
            self._restart()
            time.sleep(2)

    def _disable_mods(self, mods, keep_state=True, restart=True):
        '''take a list of modules to disable'''
        for mod in mods:
            self.__disable_mod(mod, keep_state)
        if restart:
            self._restart()
            time.sleep(2)

    def __enable_mod(self, mod, keep_state=True):

        if self._mod_enabled(mod) == False:
            if keep_state:
                self.enabled_mods += [mod]

            rc, report = testlib.cmd(['a2enmod', mod])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def _enable_mod(self, mod, keep_state=True, restart=True):
        self.__enable_mod(mod, keep_state)
        # for some reason, force-reload doesn't work
        # if self.lsb_release['Release'] >= 8.04:
        #    self._reload()
        # else:
        if restart:
            self._restart()
            time.sleep(2)

    def _enable_mods(self, mods, keep_state=True):
        '''take a list of modules to enable'''
        for mod in mods:
            self.__enable_mod(mod, keep_state)
        # for some reason, force-reload doesn't work
        # if self.lsb_release['Release'] >= 8.04:
        #    self._reload()
        # else:
        self._restart()
        time.sleep(2)

    def __disable_conf(self, conf):
        if not os.path.exists(os.path.join("/etc/apache2/conf-available", conf + \
                                       ".conf")):
            return
        if not os.path.exists("/usr/sbin/a2disconf"):
            return
        rc, report = testlib.cmd(['a2disconf', conf])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _disable_conf(self, conf):
        self.__disable_conf(conf)
        self._restart()
        time.sleep(2)

    def _disable_confs(self, confs):
        '''take a list of configs to disable'''
        for conf in confs:
            self.__disable_conf(conf)
        self._restart()
        time.sleep(2)

    def __enable_conf(self, conf):
        rc, report = testlib.cmd(['a2enconf', conf])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _enable_conf(self, conf):
        self.__enable_conf(conf)
        # for some reason, force-reload doesn't work
        # if self.lsb_release['Release'] >= 8.04:
        #    self._reload()
        # else:
        self._restart()
        time.sleep(2)

    def _enable_confs(self, confs):
        '''take a list of configs to enable'''
        for conf in confs:
            self.__enable_conf(conf)
        # for some reason, force-reload doesn't work
        # if self.lsb_release['Release'] >= 8.04:
        #    self._reload()
        # else:
        self._restart()
        time.sleep(2)

    def _disable_site(self, sitename):
        rc, report = testlib.cmd(['a2dissite', sitename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._restart()
        time.sleep(2)

    def _enable_site(self, sitename):
        rc, report = testlib.cmd(['a2ensite', sitename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        # for some reason, force-reload doesn't work
        # if self.lsb_release['Release'] >= 8.04:
        #    self._reload()
        #else:
        self._restart()
        time.sleep(2)

    def _reload(self):
        '''Reload httpd'''
        expected = 0
        if self.initdaemon == 'upstart':
            rc, report = testlib.cmd(['reload', self.initscript])
        else:
            rc, report = testlib.cmd([self.initscript, 'force-reload'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _restart(self):
        '''Restart httpd'''
        self._stop()
        self._start()

    def _prepare_ssl(self, srvkey, srvcert):
        '''Prepare Apache for ssl connections'''
        self._enable_mod("ssl")

        # copy instead of rename so we don't get invalid cross-device link errors
        shutil.copy(srvkey, self.ssl_key)
        shutil.copy(srvcert, self.ssl_crt)

        if self.lsb_release['Release'] <= 7.04:
            testlib.config_replace(self.ports_file, "Listen 443", True)

        # create the conffile entry
        site_contents = '''
NameVirtualHost *:443
<VirtualHost *:443>
        SSLEngine on
        SSLOptions +StrictRequire
        SSLCertificateFile /etc/ssl/certs/server.crt
        SSLCertificateKeyFile /etc/ssl/private/server.key

        ServerAdmin webmaster@localhost

        DocumentRoot %s/
        ErrorLog /var/log/apache2/error.log

        # Possible values include: debug, info, notice, warn, error, crit,
        # alert, emerg.
        LogLevel warn

        CustomLog /var/log/apache2/access.log combined
        ServerSignature On
</VirtualHost>
''' % self.document_root
        testlib.create_fill(self.ssl_site, site_contents)
        self._reload()

    def _test_url_proxy(self, url="http://localhost/", content="", proxy="localhost:3128"):
        '''Test the given url'''
        rc, report = testlib.cmd(['elinks', '-verbose', '2', '-no-home', '1', '-eval', 'set protocol.ftp.proxy.host = "%s"' %(proxy), '-eval', 'set protocol.http.proxy.host = "%s"' %(proxy), '-eval', 'set protocol.https.proxy.host = "%s"' %(proxy), '-dump', url])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if content != "":
            self._word_find(report, content)

    def _test_url(self, url="http://localhost/", content="", invert=False, source=False):
        '''Test the given url'''
        if source:
            report = self._get_page_source(url)
        else:
            report = self._get_page(url)

        if content != "":
            self._word_find(report, content, invert)

    def _get_page_source(self, url="http://localhost/", data='', headers=None):
        '''Fetch html source'''
        cookies = "/tmp/cookies.lwp"
        testlib.create_fill(cookies, "#LWP-Cookies-2.0")

        if headers == None:
            headers = {'User-agent' : 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)'}

        clean_url = url
        if re.search(r'http(|s)://.*:.*@[a-z].*', url):
            tmp = re.sub(r'^http(|s)://', '', url)
            username = tmp.split('@')[0].split(':')[0]
            password = tmp.split('@')[0].split(':')[1]
            base64_str = base64.encodestring('%s:%s' % (username, password))[:-1]
            headers['Authorization'] = "Basic %s" % (base64_str)
            # strip out the username and password from the url
            clean_url = re.sub(r'%s:%s@' % (username, password), '', url)

        cj = cookielib.LWPCookieJar(filename=cookies)
        cj.load()

        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        urllib2.install_opener(opener)

        try:
            if data != '':
                req = urllib2.Request(clean_url, data, headers)
            else:
                req = urllib2.Request(clean_url, headers=headers)
        except:
            raise

        tries = 0
        failed = True
        while tries < 3:
            try:
                handle = urllib2.urlopen(req)
                failed = False
                break
            except urllib2.HTTPError, e:
                raise
                if e.code != 503:
                    # for debugging
                    #print >>sys.stderr, 'Error retrieving page "url=%s", "data=%s"' % (url, data)
                    raise
            tries += 1
            time.sleep(2)

        self.assertFalse(failed, 'Could not retrieve page "url=%s", "data=%s"' % (url, data))
        html = handle.read()
        cj.save()

        return html

    def _get_page(self, url="http://localhost/"):
        '''Get contents of given url'''
        rc, report = testlib.cmd(['elinks', '-verbose', '2', '-no-home', '1', '-dump', url])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return report

    def _test_raw(self, request="", content="", host="localhost", port=80, invert = False, limit=1024):
        '''Test the given url with a raw socket to include headers'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(request)
        data = s.recv(limit)
        s.close()

        if content != "":
            self._word_find(data, content, invert = invert)

def create_php_page(page, php_content=None):
    '''Create a basic php page'''

    # complexity here is due to maintaining interface compatability when
    # php_content is not provided
    if not php_content:
        str = "php works"
        php_content = "echo '" + str + "'; "
    else:
        str = php_content
    script = '''<?php
%s
?>''' %(php_content)
    testlib.create_fill(page, script)
    return str

def create_perl_script(page):
    '''Create a basic perl script'''
    str = "perl works"
    script = '''#!/usr/bin/perl
print "Content-Type: text/plain\\n\\n";
print "''' + str + '''\\n";

'''
    testlib.create_fill(page, script, 0755)

    return str

def create_html_page(page):
    '''Create html page'''
    str = "html works"
    testlib.create_fill(page, "<html><body>" + str + "</body></html>")
    return str

