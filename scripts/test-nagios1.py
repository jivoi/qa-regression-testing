#!/usr/bin/python
#
#    test-nagios1.py quality assurance test script
#
#    Copyright (C) 2008 Canonical Ltd.
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
  DO NOT RUN ON A PRODUCTION SERVER
  *** IMPORTANT ***

  How to run in a vm:
    $ sudo apt-get -y install curl elinks nagios-text
    $ sudo ./test-nagios1.py -v

  TODO:
    - Make _post_nagios_command build the url from parameters
    - Test all commands
    - Test email alerts
    - Test plugins, like snmp, etc.
    - Test nagios-mysql and nagios-pgsql
'''

import unittest, subprocess, os, os.path, time, re
import testlib
import sys

test_client = ""

class Nagios1Common(testlib.TestlibCase):
    '''Common routines for testing Nagios1.'''
    def _setUp(self):
        '''Common test setup'''
        self.htpasswd = "/etc/nagios/htpasswd.users"
        self.nagios_cfg = "/etc/nagios/nagios.cfg"
        self.nagios_cmd = "/var/run/nagios/nagios.cmd"
        self.apache_symlink = "/etc/apache/conf.d/nagiostest.conf"
        self.nagios_hosts = "/etc/nagios/hosts.cfg"
        self.nagios_services = "/etc/nagios/services.cfg"
        self.nagios_hostgroups = "/etc/nagios/hostgroups.cfg"
        self.nagios_status = "/var/cache/nagios/status.sav"
        self.nagios_pid = "/var/run/nagios/nagios.pid"
        self.apache_pid = "/var/run/apache.pid"

        # Make sure we're not running first
        self.apachedaemon = testlib.TestDaemon("/etc/init.d/apache")
        self.nagiosdaemon = testlib.TestDaemon("/etc/init.d/nagios")
        if os.path.exists(self.nagios_pid) or os.path.exists(self.apache_pid):
            self.nagiosdaemon.stop()
            self.apachedaemon.stop()
            time.sleep(2)

        testlib.config_replace(self.htpasswd, "", True)
        rc, report = testlib.cmd(['htpasswd', '-c', '-b', self.htpasswd, 'nagiosadmin', 'ubuntu'])

        # Turn on external commands
        testlib.config_replace(self.nagios_cfg, "", True)
        subprocess.call(['sed', '-i', 's/^check_external_commands=0/check_external_commands=1/g', self.nagios_cfg])

        # Setup nagios with apache
        if os.path.exists(self.apache_symlink):
            os.unlink(self.apache_symlink)
        os.symlink('/etc/nagios/apache.conf', self.apache_symlink)

        # Add a default host to the config
        self._add_localhost_config()

        self._start()

    def _tearDown(self):
        '''Common test tear down'''
        self._stop()

        self._remove_localhost_config()

        os.unlink(self.apache_symlink)

        testlib.config_restore(self.htpasswd)
        testlib.config_restore(self.nagios_cfg)

    def _start(self):
        '''Startup with each test'''
        rc, result = self.nagiosdaemon.start()
        self.assertTrue(rc, result)
        self.assertTrue(testlib.check_pidfile('nagios', self.nagios_pid), 'Nagios is not running')

        rc, result = self.apachedaemon.start()
        self.assertTrue(rc, result)
        self.assertTrue(testlib.check_pidfile('apache', self.apache_pid), 'Apache is not running')

    def _stop(self):
        '''Stop with each test'''
        rc, result = self.nagiosdaemon.stop()
        self.assertTrue(rc, result)
        rc, result = self.apachedaemon.stop()
        self.assertTrue(rc, result)
        time.sleep(2)

    def _restart(self):
        '''Shutdown and startup with each test'''
        self._stop()
        self._start()

    def _add_localhost_config(self):
        testlib.config_replace(self.nagios_hosts, '''#
define host{
	use			generic-host
	host_name		localhost
	alias			LocalHost
	address			localhost
	check_command		check-host-alive
	max_check_attempts	20
	notification_interval	60
	notification_period	24x7
	notification_options	d,u,r
	}
''',append=True)

        testlib.config_replace(self.nagios_services, '''#
define service{
	use				generic-service
	host_name			localhost
	service_description		HTTP
	is_volatile			0
	check_period			24x7
	max_check_attempts		3
	normal_check_interval		5
	retry_check_interval		1
	contact_groups			router-admins
	notification_interval		120
	notification_period		24x7
	notification_options		w,u,c,r
	check_command			check_http
	}
''',append=True)

        testlib.config_replace(self.nagios_hostgroups, '''#
define hostgroup{
        hostgroup_name  ubuntuservers
        alias           Ubuntu Servers
        contact_groups  router-admins
        members         localhost
        }
''',append=True)

        current_time = time.time()

        testlib.config_replace(self.nagios_status,
                               '# Nagios 1.3 Retention File\n' +
                               'CREATED: %lu\n' % current_time +
                               'PROGRAM: 1;1;1;1;0;0;1;0\n' +
                               'HOST: localhost;0;%lu;1;227;0;0;0;0;1;0;0;0;1;1;%lu;(Host assumed to be up)\n'
                               % (current_time, current_time) +
                               'SERVICE: localhost;HTTP;0;%lu;0;227;0;0;0;0;0;1;1;1;1;0;1;1;1;1;%lu;'
                               % (current_time, current_time) +
                               "HTTP OK HTTP/1.1 200 OK - 5528 bytes in 0.003 seconds\x00\n",
                               append=False)

        subprocess.call(['chown', 'nagios:nagios', self.nagios_status])
        subprocess.call(['chmod', '664', self.nagios_status])

    def _remove_localhost_config(self):
        testlib.config_restore(self.nagios_hosts)
        testlib.config_restore(self.nagios_services)
        testlib.config_restore(self.nagios_hostgroups)
        testlib.config_restore(self.nagios_status)

    def _regex_find(self,report,content):
        '''Check for a specific regex'''
        warning = 'Could not find "%s"\n' % content
        self.assertTrue(re.search(content, report), warning + report)

    def _test_nagios_url(self, url="", regex="", auth="nagiosadmin:ubuntu"):
        '''Test the given nagios url'''
        if auth != "":
            fullurl = "http://" + auth +"@localhost/" + url
        else:
            fullurl = "http://localhost/" + url

        rc, report = testlib.cmd(['elinks', '-verbose', '2', '-no-home', '1', '-dump', fullurl])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if regex != "":
            self._regex_find(report, regex)

        return report

    def _test_nagios_service(self, regex="", host="localhost", service="HTTP", timeout=120):
        '''Test the given nagios service'''
        while (timeout > 0):
            report = self._test_nagios_url("/nagios/cgi-bin/extinfo.cgi?type=2&host=" + host +
                                           "&service=" + service)
            if re.search(regex, report):
                break
            time.sleep(5)
            timeout -= 5
        warning = 'Timed out trying to find "%s"\n' % regex
        self.assertTrue(re.search(regex, report), warning + report)
        
    def _send_nagios_command(self, command):
        '''Send a command to the nagios command file'''
        commandstring = "[%lu] " % time.time() + command + "\n"
        open(self.nagios_cmd, 'a').write(commandstring)

    def _post_nagios_command(self, command, auth="nagiosadmin:ubuntu", regex="was successfully submitted"):
        '''Post a command to nagios cmd.cgi'''
        rc, report = testlib.cmd(['curl', '-u', auth, 'http://localhost/nagios/cgi-bin/cmd.cgi', '--data', command])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._regex_find(report, regex)


class Nagios1Generic(Nagios1Common):
    '''Nagios 1 generic tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_webaccess_without_auth(self):
        '''(Nagios1Generic) Test connection without auth'''
        self._test_nagios_url("nagios", "Authorization Required", auth="")

    def test_webaccess_with_auth(self):
        '''(Nagios1Generic) Test connection with proper auth'''
        self._test_nagios_url("nagios", "Nagios")

    def test_http_service(self):
        '''(Nagios1Generic) Test http service'''
        self._test_nagios_service("HTTP OK")

class Nagios1Command(Nagios1Common):
    '''Nagios 1 command tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_DISABLE_SVC_CHECK(self):
        '''(Nagios1Command) Test DISABLE_SVC_CHECK'''
        self._send_nagios_command("DISABLE_SVC_CHECK;localhost;HTTP")
        self._test_nagios_service("Service Checks:\s+DISABLED")

        self._send_nagios_command("ENABLE_SVC_CHECK;localhost;HTTP")
        self._test_nagios_service("Service Checks:\s+ENABLED")

    def test_DISABLE_PASSIVE_SVC_CHECKS(self):
        '''(Nagios1Command) Test DISABLE_PASSIVE_SVC_CHECKS'''
        self._send_nagios_command("DISABLE_PASSIVE_SVC_CHECKS;localhost;HTTP")
        self._test_nagios_service("Passive Checks:\s+DISABLED")

        self._send_nagios_command("ENABLE_PASSIVE_SVC_CHECKS;localhost;HTTP")
        self._test_nagios_service("Passive Checks:\s+ENABLED")

    def test_ADD_SVC_COMMENT(self):
        '''(Nagios1Command) Test ADD_SVC_COMMENT'''
        self._send_nagios_command("ADD_SVC_COMMENT;localhost;HTTP;0;Ubuntu QA Scripts;UbuntuRocks")
        self._test_nagios_service("UbuntuRocks")

class Nagios1CGI(Nagios1Common):
    '''Nagios 1 CGI command tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_DISABLE_SVC_CHECK(self):
        '''(Nagios1CGI) Test DISABLE_SVC_CHECK'''
        self._post_nagios_command("cmd_typ=6&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Service Checks:\s+DISABLED")

        self._post_nagios_command("cmd_typ=5&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Service Checks:\s+ENABLED")

    def test_DISABLE_PASSIVE_SVC_CHECKS(self):
        '''(Nagios1CGI) Test DISABLE_PASSIVE_SVC_CHECKS'''
        self._post_nagios_command("cmd_typ=40&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Passive Checks:\s+DISABLED")

        self._post_nagios_command("cmd_typ=39&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Passive Checks:\s+ENABLED")

    def test_ADD_SVC_COMMENT(self):
        '''(Nagios1CGI) Test ADD_SVC_COMMENT'''
        self._post_nagios_command("cmd_typ=3&cmd_mod=2&host=localhost&service=HTTP" \
                                  "&com_author=Ubuntutest&com_data=UbuntuRocks&btnSubmit=Commit")
        self._test_nagios_service("UbuntuRocks")

class Nagios1Security(Nagios1Common):
    '''Nagios 1 security'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_command_injection(self):
        '''(Nagios1Security) Test command injection'''
        # This should give an error message, as commands are now parsed for hidden
        # linefeeds by the CVE-2008-5027 fix.
        self._post_nagios_command("cmd_typ=3&cmd_mod=2&host=localhost&service=HTTP" \
                                  "&btnSubmit=Commit&com_author=Ubuntutest" \
                                  "&com_data=UbuntuRocks%0a%5b1229526917%5d%20DEL_SVC_COMMENT",
                                  regex = "An error occurred")


class Nagios1Stub(Nagios1Common):
    '''Stub tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_stub(self):
        '''(Nagios1Stub) stub'''
        pass


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()

    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios1Stub))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios1Generic))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios1Command))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios1CGI))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios1Security))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
