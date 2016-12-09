#!/usr/bin/python
#
#    test-nagios2.py quality assurance test script
#
#    Copyright (C) 2008-2009 Canonical Ltd.
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
    $ sudo apt-get -y install lsb-release curl elinks apache2 nagios2
    $ sudo ./test-nagios2.py -v

  TODO:
    - Make _post_nagios_command build the url from parameters
    - Test all nagios commands
    - Test email alerts
    - Test plugins, like snmp, etc.
'''

import unittest, subprocess, os, os.path, time, re
import testlib
import sys

class Nagios2Common(testlib.TestlibCase):
    '''Common routines for testing Nagios2.'''
    def _setUp(self):
        '''Common test setup'''
        self.htpasswd = "/etc/nagios2/htpasswd.users"
        self.nagios_cfg = "/etc/nagios2/nagios.cfg"
        self.nagios_cmd = "/var/lib/nagios2/rw/nagios.cmd"
        self.apache_symlink = "/etc/apache2/conf.d/nagiostest.conf"
        self.apache_pid = "/var/run/apache2.pid"

        # Make sure we're not running first
        self.apachedaemon = testlib.TestDaemon("/etc/init.d/apache2")
        self.nagiosdaemon = testlib.TestDaemon("/etc/init.d/nagios2")
        rc, result = self.nagiosdaemon.status()
        if (rc):
            self.nagiosdaemon.stop()
            time.sleep(2)
        if os.path.exists(self.apache_pid):
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
        os.symlink('/etc/nagios2/apache2.conf', self.apache_symlink)

        # Fix permissions on command pipe dir (as per /usr/share/doc/nagios3/README.Debian)
        subprocess.call(['chmod', 'g+xs', '/var/lib/nagios2/rw'])
        subprocess.call(['chmod', 'o+x', '/var/lib/nagios2'])

        self._start()

    def _tearDown(self):
        '''Common test tear down'''
        self._stop()

        subprocess.call(['chmod', 'g-xs', '/var/lib/nagios2/rw'])
        subprocess.call(['chmod', 'o-x', '/var/lib/nagios2'])

        os.unlink(self.apache_symlink)

        testlib.config_restore(self.htpasswd)
        testlib.config_restore(self.nagios_cfg)

    def _start(self):
        '''Startup with each test'''
        rc, result = self.nagiosdaemon.start()
        self.assertTrue(rc, result)
        rc, result = self.nagiosdaemon.status()
        self.assertTrue(rc, result)

        rc, result = self.apachedaemon.start()
        self.assertTrue(rc, result)
        self.assertTrue(testlib.check_pidfile('apache2', self.apache_pid), 'Apache is not running')

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
            report = self._test_nagios_url("cgi-bin/nagios2/extinfo.cgi?type=2&host=" + host +
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
        rc, report = testlib.cmd(['curl', '-u', auth, 'http://localhost/cgi-bin/nagios2/cmd.cgi', '--data', command])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._regex_find(report, regex)


class Nagios2Generic(Nagios2Common):
    '''Nagios 2 generic tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_webaccess_without_auth(self):
        '''(Nagios3Generic) Test connection without auth'''
        self._test_nagios_url("nagios2", "Authorization Required", auth="")

    def test_webaccess_with_auth(self):
        '''(Nagios3Generic) Test connection with proper auth'''
        self._test_nagios_url("nagios2", "Nagios")

    def test_http_service(self):
        '''(Nagios3Generic) Test http service'''
        # Force a check right away
        self._send_nagios_command("SCHEDULE_FORCED_SVC_CHECK;localhost;HTTP;1000000000")
        self._test_nagios_service("HTTP OK")

class Nagios2Command(Nagios2Common):
    '''Nagios 2 command tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_DISABLE_SVC_CHECK(self):
        '''(Nagios2Command) Test DISABLE_SVC_CHECK'''
        self._send_nagios_command("DISABLE_SVC_CHECK;localhost;HTTP")
        self._test_nagios_service("Active Checks:\s+DISABLED")

        self._send_nagios_command("ENABLE_SVC_CHECK;localhost;HTTP")
        self._test_nagios_service("Active Checks:\s+ENABLED")

    def test_DISABLE_PASSIVE_SVC_CHECKS(self):
        '''(Nagios2Command) Test DISABLE_PASSIVE_SVC_CHECKS'''
        self._send_nagios_command("DISABLE_PASSIVE_SVC_CHECKS;localhost;HTTP")
        self._test_nagios_service("Passive Checks:\s+DISABLED")

        self._send_nagios_command("ENABLE_PASSIVE_SVC_CHECKS;localhost;HTTP")
        self._test_nagios_service("Passive Checks:\s+ENABLED")

    def test_STOP_OBSESSING_OVER_SVC(self):
        '''(Nagios2Command) Test STOP_OBSESSING_OVER_SVC'''
        self._send_nagios_command("STOP_OBSESSING_OVER_SVC;localhost;HTTP")
        self._test_nagios_service("Obsessing:\s+DISABLED")

        self._send_nagios_command("START_OBSESSING_OVER_SVC;localhost;HTTP")
        self._test_nagios_service("Obsessing:\s+ENABLED")

    def test_ADD_SVC_COMMENT(self):
        '''(Nagios2Command) Test ADD_SVC_COMMENT'''
        self._send_nagios_command("ADD_SVC_COMMENT;localhost;HTTP;0;Ubuntu QA Scripts;UbuntuRocks")
        self._test_nagios_service("UbuntuRocks")

class Nagios2CGI(Nagios2Common):
    '''Nagios 2 CGI command tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_DISABLE_SVC_CHECK(self):
        '''(Nagios2CGI) Test DISABLE_SVC_CHECK'''
        self._post_nagios_command("cmd_typ=6&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Active Checks:\s+DISABLED")

        self._post_nagios_command("cmd_typ=5&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Active Checks:\s+ENABLED")

    def test_DISABLE_PASSIVE_SVC_CHECKS(self):
        '''(Nagios2CGI) Test DISABLE_PASSIVE_SVC_CHECKS'''
        self._post_nagios_command("cmd_typ=40&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Passive Checks:\s+DISABLED")

        self._post_nagios_command("cmd_typ=39&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Passive Checks:\s+ENABLED")

    def test_STOP_OBSESSING_OVER_SVC(self):
        '''(Nagios2CGI) Test STOP_OBSESSING_OVER_SVC'''
        self._post_nagios_command("cmd_typ=100&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Obsessing:\s+DISABLED")

        self._post_nagios_command("cmd_typ=99&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Obsessing:\s+ENABLED")

    def test_ADD_SVC_COMMENT(self):
        '''(Nagios2CGI) Test ADD_SVC_COMMENT'''
        self._post_nagios_command("cmd_typ=3&cmd_mod=2&host=localhost&service=HTTP" \
                                  "&com_author=Ubuntutest&com_data=UbuntuRocks&btnSubmit=Commit")
        self._test_nagios_service("UbuntuRocks")

    def test_statuswml_ping(self):
        '''(Nagios2CGI) Test statuswml.cgi ping command'''
        url = "nagios2/cgi-bin/statuswml.cgi?ping=127.0.0.1"
        self._test_nagios_url(url, "PING 127.0.0.1")

    def test_statuswml_traceroute(self):
        '''(Nagios2CGI) Test statuswml.cgi traceroute command'''
        url = "nagios2/cgi-bin/statuswml.cgi?traceroute=127.0.0.1"
        self._test_nagios_url(url, "Results For Traceroute To 127.0.0.1")

class Nagios2Security(Nagios2Common):
    '''Nagios 2 security'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_CHANGE_commands(self):
        '''(Nagios2Security) Test CHANGE commands'''
        self._send_nagios_command("CHANGE_SVC_CHECK_COMMAND;localhost;HTTP;check_ssh")
        self._send_nagios_command("SCHEDULE_FORCED_SVC_CHECK;localhost;HTTP;1000000000")

        time.sleep(20)
        # This shouldn't have changed to "SSH OK", as CHANGE commands should be disabled
        # by the CVE-2008-5028 fix. A newer Nagios version may re-enable the CHANGE
        # commands and fix the problem another way though, so this will need to be
        # adapted to the newer way in the future.
        self._test_nagios_service("HTTP OK")

    def test_command_injection(self):
        '''(Nagios2Security) Test command injection'''
        # This should give an error message, as commands are now parsed for hidden
        # linefeeds by the CVE-2008-5027 fix.
        self._post_nagios_command("cmd_typ=3&cmd_mod=2&host=localhost&service=HTTP" \
                                  "&btnSubmit=Commit&com_author=Ubuntutest" \
                                  "&com_data=UbuntuRocks%0a%5b1229526917%5d%20DEL_SVC_COMMENT",
                                  regex = "An error occurred")

    def test_cve_2009_2288(self):
        '''(Nagios2Security) Test CVE-2009-2288'''
        magic_string = "UbuntuRocks"

        for command in ['ping', 'traceroute']:
            url = "nagios2/cgi-bin/statuswml.cgi?" + command + "=127.0.0.1%3Becho+" + magic_string

            report = self._test_nagios_url(url, "Invalid host name/ip")
        
            warning = 'The server returned "%s"!!!\n' % magic_string
            self.assertFalse(re.search(magic_string, report), warning + report)


class Nagios2Stub(Nagios2Common):
    '''Stub tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_stub(self):
        '''(Nagios2Stub) stub'''
        pass


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()

    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios2Stub))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios2Generic))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios2Command))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios2CGI))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios2Security))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)