#!/usr/bin/python
#
#    test-tomcat.py quality assurance test script for tomcat
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
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release elinks tomcat6 tomcat6-examples tomcat6-admin curl libapache2-mod-jk && ./test-tomcat.py tomcat6 -v'

    NOTE: these tests are sensitive to high host load so it is best to do
          test runs sequentially if running under multiple VMs on the host
'''

import unittest, subprocess, sys, os, socket, shutil
import errno
import testlib
import testlib_httpd

exe = ""

use_private = True
try:
    from private.qrt.tomcat import TomcatPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class TomcatTest(testlib.TestlibCase):
    '''Test tomcat.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tomcat_daemon = testlib.TestDaemon("/etc/init.d/" + exe)
        self.users_file="/etc/" + exe + "/tomcat-users.xml"
        self.html_page = "/var/lib/" + exe + "/webapps/ROOT/test.html"
        self.webapp_dir = "/var/lib/" + exe + "/webapps"
        self.war = ""

        self.admin_user = "tomcatadmin"
        #self.admin_pass = "tomcatpass"
        self.admin_pass = testlib.random_string(10)
        testlib.config_replace(self.users_file, "", True)
        self.manager_group = "manager"
        if exe in ["tomcat7", "tomcat8"]:
            self.manager_group = "manager-gui"
        user_config = 's/^<tomcat-users>/<tomcat-users>\\n<role rolename=\"%s\"\/>\\n<user username=\"%s\" password=\"%s\" roles=\"%s\"\/>\\n/' % (self.manager_group, self.admin_user, self.admin_pass, self.manager_group)
        if exe in ["tomcat8"]:
            user_config = 's/^<\/tomcat-users>/<role rolename=\"%s\"\/>\\n<user username=\"%s\" password=\"%s\" roles=\"%s\"\/>\\n<\/tomcat-users>\\n/' % (self.manager_group, self.admin_user, self.admin_pass, self.manager_group)

        subprocess.call(['sed', '-i', user_config, self.users_file])
        subprocess.call(['chgrp', exe, self.users_file])

        self.tomcat_daemon.restart()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.tomcat_daemon.stop()

        testlib.config_restore(self.users_file)
        subprocess.call(['chgrp', exe, self.users_file])

        if self.war != "" and os.path.exists(os.path.join(self.webapp_dir,self.war)):
            self._cleanup_war(self.war)

    def _deploy_war(self,war_name):
        '''Deploys a war file'''
        # Server needs to restart to extract the war file
        self.tomcat_daemon.stop()
        shutil.copy(os.path.join('./tomcat', war_name), self.webapp_dir)
        self.war = war_name
        self.tomcat_daemon.start()

    def _setup_auth(self, auth_type="BASIC"):
        '''Deploys a war file to test auth'''

        self._deploy_war("helloworld.war")

        # Visit the site so the war gets extracted by tomcat7
        self._test_url("http://localhost:8080/helloworld/hi.jsp", 'Hello, World')

        # We need to stop the server again or it won't pick up the web.xml
        # change. Yes, this sucks.
        self.tomcat_daemon.stop()
        war_web_xml = os.path.join(self.webapp_dir, "helloworld/WEB-INF/web.xml")

        testlib.create_fill(war_web_xml, '''
<web-app>
	<display-name>Hello World</display-name>
	<security-constraint>
		<web-resource-collection>
			<web-resource-name>Entire Application</web-resource-name>
			<url-pattern>/*</url-pattern>
		</web-resource-collection>
		<auth-constraint>
			<role-name>%s</role-name>
		</auth-constraint>
	</security-constraint>

	<login-config>
		<auth-method>%s</auth-method>
		<realm-name>%s Authentication</realm-name>
	</login-config>
	<security-role>
		<role-name>%s</role-name>
	</security-role>
</web-app>
''' % (self.manager_group, auth_type, auth_type, self.manager_group))
        self.tomcat_daemon.start()

    def _cleanup_war(self,war_name):
        '''Removes a war file and directory'''

        war_file = os.path.join(self.webapp_dir, war_name)
        war_dir = os.path.join(self.webapp_dir, war_name.split('.')[0])

        if os.path.exists(war_file):
            os.unlink(war_file)

        if os.path.exists(war_dir):
            testlib.recursive_rm(war_dir)

        self.war = ""

    def _word_find(self,report,content, invert=False):
        '''Check for a specific string'''
        if invert == False:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(content in report, warning + report)
        else:
            warning = 'Found "%s"\n' % content
            self.assertFalse(content in report, warning + report)

    def _test_url(self, url="http://localhost:8080/", content="", invert=False, source=False):
        '''Test the given url'''
        command=['elinks', '-verbose', '2', '-no-home', '1']

        if source == True:
            command.extend(['-source', '1', url])
        else:
            command.extend(['-dump', url])

        rc, report = testlib.cmd(command)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if content != "":
            self._word_find(report, content, invert=invert)

    def _test_curl(self, url="http://localhost:8080/", content="", user="", password="", invert=False):
        '''Test the given url with curl'''

        # curl support was added so we can test digest auth, it would appear
        # elinks doesn't support it from the command line.

        command=['curl', '--anyauth']

        if user != "":
            command.extend(['-u', user + ":" + password])

        command.extend([url])

        rc, report = testlib.cmd(command)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if content != "":
            self._word_find(report, content, invert=invert)

    def _test_raw(self, request="", content="", host="localhost", port=8080, invert = False, limit=4096):
        '''Test the given url with a raw socket to include headers'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(request)
        data = s.recv(limit)
        s.close()

        if content != "":
            self._word_find(data, content, invert = invert)

        return data

    def _create_html_page(self,page):
        '''Create html page'''
        str = "html works"
        testlib.create_fill(page, "<html><body>" + str + "</body></html>")
        return str

    def test_aa_daemon(self):
        '''Test daemon'''
        self.tomcat_daemon.status()

    def test_aa_http(self):
        '''Test http'''
        self._test_url("http://localhost:8080/", "It works !")

        test_str = self._create_html_page(self.html_page)
        self._test_url("http://localhost:8080/" + \
                       os.path.basename(self.html_page), test_str)

    def test_aa_servlets(self):
        '''Test servlet examples'''

        tests = ( ('examples/servlets/servlet/HelloWorldExample', 'Hello World!'),
                  ('examples/servlets/servlet/RequestInfoExample', 'Method:'),
                  ('examples/servlets/servlet/RequestHeaderExample', 'user-agent'),
                  ('examples/servlets/servlet/RequestParamExample', 'No Parameters'),
                  ('examples/servlets/servlet/SessionExample', 'Session ID') )

        for url, result in tests:
            self._test_url("http://localhost:8080/" + url, result)

    def test_aa_jsp(self):
        '''Test jsp examples'''

        # libraries in /usr/share/tomcat6-examples/examples/WEB-INF/lib
        # got removed in lucid because of debian bug #528119
        if self.lsb_release['Release'] >= 10.04:
            tests = ( ('examples/jsp/jsp2/el/basic-arithmetic.jsp', 'Infinity'),
                      ('examples/jsp/jsp2/el/basic-comparisons.jsp', 'true'),
                      ('examples/jsp/jsp2/simpletag/hello.jsp', 'Hello, world!'),
                      ('examples/jsp/jsp2/simpletag/repeat.jsp', 'Invocation 5 of 5'),
                      ('examples/jsp/jsp2/simpletag/book.jsp', 'THE LORD OF THE RINGS') )
        else:
            tests = ( ('examples/jsp/jsp2/el/basic-arithmetic.jsp', 'Infinity'),
                      ('examples/jsp/jsp2/el/basic-comparisons.jsp', 'true'),
                      ('examples/jsp/jsp2/el/implicit-objects.jsp?foo=ubunturocks', 'ubunturocks'),
                      ('examples/jsp/jsp2/el/functions.jsp?foo=ubunturocks', 'skcorutnubu'),
                      ('examples/jsp/jsp2/simpletag/hello.jsp', 'Hello, world!'),
                      ('examples/jsp/jsp2/simpletag/repeat.jsp', 'Invocation 5 of 5'),
                      ('examples/jsp/jsp2/simpletag/book.jsp', 'THE LORD OF THE RINGS') )



        for url, result in tests:
            self._test_url("http://localhost:8080/" + url, result)

    def test_aa_war(self):
        '''Deploy a war file'''

        self._deploy_war('helloworld.war')
        self._test_url("http://localhost:8080/helloworld/hi.jsp", 'Hello, World')

    def test_aa_manager(self):
        '''Test management page'''

        url = "http://%s:%s@localhost:8080/manager/html" % (self.admin_user, self.admin_pass)

        self._test_url(url, "Application Manager")

    def test_auth_basic(self):
        '''Test basic auth'''

        self._setup_auth()

        url = "http://localhost:8080/helloworld/hi.jsp"
        self._test_curl(url, 'Hello, World', self.admin_user, self.admin_pass)

    def test_auth_basic_missing(self):
        '''Test basic auth with no password'''

        self._setup_auth()

        url = "http://localhost:8080/helloworld/hi.jsp"
        self._test_curl(url, 'HTTP Status 401')

    def test_auth_basic_bad(self):
        '''Test basic auth with bad password'''

        self._setup_auth()

        url = "http://localhost:8080/helloworld/hi.jsp"
        self._test_curl(url, 'HTTP Status 401', "Ubuntu", "Rocks")

    def test_auth_digest(self):
        '''Test digest auth'''

        self._setup_auth(auth_type="DIGEST")

        url = "http://localhost:8080/helloworld/hi.jsp"
        self._test_curl(url, 'Hello, World', self.admin_user, self.admin_pass)

    def test_auth_digest_missing(self):
        '''Test digest auth with no password'''

        self._setup_auth(auth_type="DIGEST")

        url = "http://localhost:8080/helloworld/hi.jsp"
        self._test_curl(url, 'HTTP Status 401')

    def test_auth_digest_bad(self):
        '''Test digest auth with bad password'''

        self._setup_auth(auth_type="DIGEST")

        url = "http://localhost:8080/helloworld/hi.jsp"
        self._test_curl(url, 'HTTP Status 401', "Ubuntu", "Rocks")

    def test_cve_2008_5515(self):
        '''Test CVE-2008-5515'''

        if exe in ["tomcat8"]:
            return self._skipped("FIXME: _test_raw doesn't work with tomcat8")

        testlib.create_fill('/usr/share/' + exe + '-examples/examples/jsp/test.jsp', '''
<%
request.getRequestDispatcher( "bar.jsp?somepar=someval&par=" +
    request.getParameter( "blah" ) ).forward( request, response );
%>
''')

        request = "GET /examples/jsp/test.jsp?blah=/../../WEB-INF/web.xml HTTP/1.1\nHost: localhost\nConnection: close\n\n"
        self._test_raw(request, 'Licensed to the Apache', invert=True)
        self._test_raw(request, 'is not available.')

    def x_test_cve_2009_0580(self):
        '''Test CVE-2009-0580'''

        self._skipped("Can't reproduce")
        return

        request = "POST /examples/jsp/security/protected/j_security_check HTTP/1.1\nHost: localhost\n\nj_username=tomcat&j_password=%\n\n"
        data = self._test_raw(request, '', limit=4000)
        print "The data was: '%s'" % data

    def test_cve_2009_0781(self):
        '''Test CVE-2009-0781'''

        if exe in ["tomcat8"]:
            return self._skipped("FIXME: _test_raw doesn't work with tomcat8")

        request = "GET http://localhost:8080/examples/jsp/cal/cal2.jsp?time=8am%20STYLE=xss:e/**/xpression(try{a=firstTime}catch(e){firstTime=1;alert('XSS')}); HTTP/1.1\nHost: localhost\nConnection: close\n\n"
        self._test_raw(request, 'VALUE=8am', invert=True)
        self._test_raw(request, 'VALUE="8am')

    def test_cve_2009_2693(self):
        '''Test CVE-2009-2693'''

        self._deploy_war('hellodotdot.war')

        bad_file = os.path.join(self.webapp_dir,'nogood.txt')
        if os.path.exists(bad_file):
            os.unlink(bad_file)
            self.fail('found %s!!' % bad_file)

        self._test_url("http://localhost:8080/hellodotdot/hi.jsp", 'HTTP Status 404')

    def disabled_test_cve_2010_4172(self):
        '''Test CVE-2010-4172'''

        # This test is now disabled, as the fix for CVE-2012-4431 broke it

        # Session manager doesn't even work on karmic
        if self.lsb_release['Release'] == 9.10:
            return self._skipped("Session manager doesn't work on karmic")

        base_url = "http://%s:%s@localhost:8080/" % (self.admin_user, self.admin_pass)
        page = "manager/html/sessions?path=/manager&sort=CreationTsdfsdf%22%3E%3Cblink%3EXSS!%3C/blink%3E"

        self._test_url(base_url + page, "Sessions Administration")
        self._test_url(base_url + page, "XSS", invert=True)

    def test_cve_2011_0013(self):
        '''Test CVE-2011-0013'''

        self._deploy_war('cve-2011-0013.war')
        url = "http://%s:%s@localhost:8080/manager/html" % (self.admin_user, self.admin_pass)

        self._test_url(url, '<XSS>', source=True, invert=True)
        self._test_url(url, 'Test&lt;XSS&gt;Test', source=True)

class TomcatApacheTest(testlib_httpd.HttpdCommon):
    '''Test basic tomcat functionality with apache'''
    def setUp(self):
        '''Setup mechanisms'''
        if self.lsb_release['Release'] >= 13.10:
            self.testlib_conf = "/etc/apache2/conf-enabled/testlib.conf"
            self.default_site = "/etc/apache2/sites-available/000-default.conf"
            self.default_vhost_link = "/etc/apache2/sites-enabled/000-default.conf"
        else:
            self.testlib_conf = "/etc/apache2/conf.d/testlib"
            self.default_site = "/etc/apache2/sites-available/default"
            self.default_vhost_link = "/etc/apache2/sites-enabled/000-default"

        self._set_initscript("/etc/init.d/apache2")
        self.ports_file = "/etc/apache2/ports.conf"
        self.tomcat_daemon = testlib.TestDaemon("/etc/init.d/" + exe)
        self.server_file="/etc/" + exe + "/server.xml"

        # Change the default port, so we can run in a schroot
        testlib.config_replace(self.ports_file, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.ports_file])
        testlib.config_replace(self.default_site, "", append=True)
        if self.lsb_release['Release'] > 8.04:
            subprocess.call(['sed', '-i', 's/80/8000/g', self.default_site])
        else:
            subprocess.call(['sed', '-i', 's/\(VirtualHost \*\)/\\1\:8000/', self.default_site])

        # Set up jk configuration
        if self.lsb_release['Release'] < 11.10:
            contents = '''
JkWorkersFile	/etc/libapache2-mod-jk/workers.properties
JkLogFile 	/var/log/apache2/mod_jk.log
JkLogLevel 	info
JkMount /*.jsp ajp13_worker
JkMount /*/servlet/ ajp13_worker
'''
            testlib.create_fill(self.testlib_conf, contents)
        subprocess.call(['sed', '-i', 's#^</VirtualHost>#JkMount /examples* ajp13_worker\\n</VirtualHost>#', self.default_site])

        testlib.config_replace(self.server_file, "", append=True)
        subprocess.call(['sed', '-i', 's#</Service>#<Connector port="8009" protocol="AJP/1.3" redirectPort="8443" />\\n</Service>#', self.server_file])

        self.tomcat_daemon.restart()

        # ensure sites-enabled/000-default is a symlink to
        # sites-available/default, or else tests will fail.
        try:
            if os.path.abspath(os.path.join('/etc/apache2/sites-enabled/', os.readlink(self.default_vhost_link))) == self.default_site:
                pass
        except OSError, e:
            if e.errno == errno.ENOENT or e.errno == errno.EINVAL:
                if os.path.exists(self.default_vhost_link):
                    testlib._save_backup(self.default_vhost_link)
                    os.unlink(self.default_vhost_link)
                os.symlink(self.default_site, self.default_vhost_link)
            else:
                raise e

        if self.lsb_release['Release'] >= 13.10:
            self._enable_mods(["jk"], keep_state=False)

        testlib_httpd.HttpdCommon._setUp(self)


    def tearDown(self):
        '''Shutdown methods'''
        if os.path.exists(self.testlib_conf):
            os.unlink(self.testlib_conf)
        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.default_site)
        testlib.config_restore(self.server_file)

        if self.lsb_release['Release'] >= 13.10:
            self._disable_mods(["jk"], keep_state=False)

        testlib_httpd.HttpdCommon._tearDown(self)
        self.tomcat_daemon.stop()

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
        self._test_url("http://localhost:8000/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost:8000/" + \
                       os.path.basename(self.html_page), test_str)

    def test_aa_servlets(self):
        '''Test servlet examples'''

        tests = ( ('examples/servlets/servlet/HelloWorldExample', 'Hello World!'),
                  ('examples/servlets/servlet/RequestInfoExample', 'Method:'),
                  ('examples/servlets/servlet/RequestHeaderExample', 'user-agent'),
                  ('examples/servlets/servlet/RequestParamExample', 'No Parameters'),
                  ('examples/servlets/servlet/SessionExample', 'Session ID') )

        for url, result in tests:
            self._test_url("http://localhost:8000/" + url, result)

    def test_aa_jsp(self):
        '''Test jsp examples'''

        # libraries in /usr/share/tomcat6-examples/examples/WEB-INF/lib
        # got removed in lucid because of debian bug #528119
        if self.lsb_release['Release'] >= 10.04:
            tests = ( ('examples/jsp/jsp2/el/basic-arithmetic.jsp', 'Infinity'),
                      ('examples/jsp/jsp2/el/basic-comparisons.jsp', 'true'),
                      ('examples/jsp/jsp2/simpletag/hello.jsp', 'Hello, world!'),
                      ('examples/jsp/jsp2/simpletag/repeat.jsp', 'Invocation 5 of 5'),
                      ('examples/jsp/jsp2/simpletag/book.jsp', 'THE LORD OF THE RINGS') )
        else:
            tests = ( ('examples/jsp/jsp2/el/basic-arithmetic.jsp', 'Infinity'),
                      ('examples/jsp/jsp2/el/basic-comparisons.jsp', 'true'),
                      ('examples/jsp/jsp2/el/implicit-objects.jsp?foo=ubunturocks', 'ubunturocks'),
                      ('examples/jsp/jsp2/el/functions.jsp?foo=ubunturocks', 'skcorutnubu'),
                      ('examples/jsp/jsp2/simpletag/hello.jsp', 'Hello, world!'),
                      ('examples/jsp/jsp2/simpletag/repeat.jsp', 'Invocation 5 of 5'),
                      ('examples/jsp/jsp2/simpletag/book.jsp', 'THE LORD OF THE RINGS') )



        for url, result in tests:
            self._test_url("http://localhost:8000/" + url, result)

if __name__ == '__main__':

    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        print >>sys.stderr, "Please specify the tomcat package to test (eg 'tomcat6', or 'tomcat7')"
        sys.exit(1)

    exe = sys.argv[1]

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TomcatTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TomcatApacheTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TomcatPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
