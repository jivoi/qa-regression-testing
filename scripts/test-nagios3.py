#!/usr/bin/python
#
#    test-nagios3.py quality assurance test script
#
#    Copyright (C) 2008-2013 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: curl elinks nagios3
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) and not
    on a production machine. While efforts are made to make these tests
    non-destructive, there is no guarantee this script will not alter the
    machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install lsb-release curl elinks nagios3
    $ sudo ./test-nagios3.py -v

  TODO:
    - Make _post_nagios_command build the url from parameters
    - Test all 157 commands
    - Test email alerts
    - Test plugins, like snmp, etc.
    - Make sure nagios3 generated initial values before performing tests
'''

import unittest, subprocess, time, re
import testlib
import sys

test_client = ""

class Nagios3Common(testlib.TestlibCase):
    '''Common routines for testing Nagios3.'''
    def _setUp(self):
        '''Common test setup'''
        self.htpasswd = "/etc/nagios3/htpasswd.users"
        self.nagios_cfg = "/etc/nagios3/nagios.cfg"
        self.nagios_cmd = "/var/lib/nagios3/rw/nagios.cmd"

        # Make sure we're not running first
        self.apachedaemon = testlib.TestDaemon("/etc/init.d/apache2")
        self.nagiosdaemon = testlib.TestDaemon("/etc/init.d/nagios3")
        rc, result = self.nagiosdaemon.status()
        if (rc):
            self.nagiosdaemon.stop()
            time.sleep(2)
        rc, result = self.apachedaemon.status()
        if (rc):
            self.apachedaemon.stop()
            time.sleep(2)

        testlib.config_replace(self.htpasswd, "", True)
        rc, report = testlib.cmd(['htpasswd', '-c', '-b', self.htpasswd, 'nagiosadmin', 'ubuntu'])

        # Turn on external commands
        testlib.config_replace(self.nagios_cfg, "", True)
        subprocess.call(['sed', '-i', 's/^check_external_commands=0/check_external_commands=1/g', self.nagios_cfg])

        # Fix permissions on command pipe dir (as per /usr/share/doc/nagios3/README.Debian)
        subprocess.call(['chmod', 'g+xs', '/var/lib/nagios3/rw'])
        subprocess.call(['chmod', 'o+x', '/var/lib/nagios3'])

        self._start()

    def _tearDown(self):
        '''Common test tear down'''
        self._stop()

        subprocess.call(['chmod', 'g-xs', '/var/lib/nagios3/rw'])
        subprocess.call(['chmod', 'o-x', '/var/lib/nagios3'])

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
        rc, result = self.apachedaemon.status()
        self.assertTrue(rc, result)


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

    def _test_nagios_url(self, url="", regex="", auth="nagiosadmin:ubuntu", source=False):
        '''Test the given nagios url'''

        command = ['elinks', '-verbose', '2', '-no-home', '1']

        if source == True:
            command.extend(['-source', '1'])
        else:
            command.extend(['-dump'])

        if auth != "":
            command.extend(["http://" + auth +"@localhost/" + url])
        else:
            command.extend(["http://localhost/" + url])

        rc, report = testlib.cmd(command)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if regex != "":
            self._regex_find(report, regex)

        return report

    def _test_nagios_service(self, regex="", host="localhost", service="HTTP", timeout=120):
        '''Test the given nagios service'''
        while (timeout > 0):
            report = self._test_nagios_url("cgi-bin/nagios3/extinfo.cgi?type=2&host=" + host +
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
        rc, report = testlib.cmd(['curl', '-u', auth, 'http://localhost/cgi-bin/nagios3/cmd.cgi', '--data', command])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._regex_find(report, regex)


class Nagios3Generic(Nagios3Common):
    '''Nagios 3 generic tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_webaccess_without_auth(self):
        '''(Nagios3Generic) Test connection without auth'''
        self._test_nagios_url("nagios3", "Authorization Required", auth="")

    def test_webaccess_with_auth(self):
        '''(Nagios3Generic) Test connection with proper auth'''
        self._test_nagios_url("nagios3", "Nagios")

    def test_http_service(self):
        '''(Nagios3Generic) Test http service'''
        self._test_nagios_service("HTTP OK", timeout=480)

class Nagios3Command(Nagios3Common):
    '''Nagios 3 command tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_DISABLE_SVC_CHECK(self):
        '''(Nagios3Command) Test DISABLE_SVC_CHECK'''
        self._send_nagios_command("DISABLE_SVC_CHECK;localhost;HTTP")
        self._test_nagios_service("Active Checks:[^\w]+DISABLED")

        self._send_nagios_command("ENABLE_SVC_CHECK;localhost;HTTP")
        self._test_nagios_service("Active Checks:[^\w]+ENABLED")

    def test_DISABLE_PASSIVE_SVC_CHECKS(self):
        '''(Nagios3Command) Test DISABLE_PASSIVE_SVC_CHECKS'''
        self._send_nagios_command("DISABLE_PASSIVE_SVC_CHECKS;localhost;HTTP")
        self._test_nagios_service("Passive Checks:[^\w]+DISABLED")

        self._send_nagios_command("ENABLE_PASSIVE_SVC_CHECKS;localhost;HTTP")
        self._test_nagios_service("Passive Checks:[^\w]+ENABLED")

    def test_STOP_OBSESSING_OVER_SVC(self):
        '''(Nagios3Command) Test STOP_OBSESSING_OVER_SVC'''
        self._send_nagios_command("STOP_OBSESSING_OVER_SVC;localhost;HTTP")
        self._test_nagios_service("Obsessing:[^\w]+DISABLED")

        self._send_nagios_command("START_OBSESSING_OVER_SVC;localhost;HTTP")
        self._test_nagios_service("Obsessing:[^\w]+ENABLED")

    def test_ADD_SVC_COMMENT(self):
        '''(Nagios3Command) Test ADD_SVC_COMMENT'''
        self._send_nagios_command("ADD_SVC_COMMENT;localhost;HTTP;0;Ubuntu QA Scripts;UbuntuRocks")
        self._test_nagios_service("UbuntuRocks")

class Nagios3CGI(Nagios3Common):
    '''Nagios 3 CGI command tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_DISABLE_SVC_CHECK(self):
        '''(Nagios3CGI) Test DISABLE_SVC_CHECK'''
        self._post_nagios_command("cmd_typ=6&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Active Checks:[^\w]+DISABLED")

        self._post_nagios_command("cmd_typ=5&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Active Checks:[^\w]+ENABLED")

    def test_DISABLE_PASSIVE_SVC_CHECKS(self):
        '''(Nagios3CGI) Test DISABLE_PASSIVE_SVC_CHECKS'''
        self._post_nagios_command("cmd_typ=40&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Passive Checks:[^\w]+DISABLED")

        self._post_nagios_command("cmd_typ=39&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Passive Checks:[^\w]+ENABLED")

    def test_STOP_OBSESSING_OVER_SVC(self):
        '''(Nagios3CGI) Test STOP_OBSESSING_OVER_SVC'''
        self._post_nagios_command("cmd_typ=100&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Obsessing:[^\w]+DISABLED")

        self._post_nagios_command("cmd_typ=99&cmd_mod=2&host=localhost&service=HTTP&btnSubmit=Commit")
        self._test_nagios_service("Obsessing:[^\w]+ENABLED")

    def test_ADD_SVC_COMMENT(self):
        '''(Nagios3CGI) Test ADD_SVC_COMMENT'''
        self._post_nagios_command("cmd_typ=3&cmd_mod=2&host=localhost&service=HTTP" \
                                  "&com_author=Ubuntutest&com_data=UbuntuRocks&btnSubmit=Commit")
        self._test_nagios_service("UbuntuRocks")

    def test_statuswml_ping(self):
        '''(Nagios3CGI) Test statuswml.cgi ping command'''
        url = "nagios3/cgi-bin/statuswml.cgi?ping=127.0.0.1"
        self._test_nagios_url(url, "PING 127.0.0.1")

    def test_statuswml_traceroute(self):
        '''(Nagios3CGI) Test statuswml.cgi traceroute command'''
        url = "nagios3/cgi-bin/statuswml.cgi?traceroute=127.0.0.1"
        self._test_nagios_url(url, "Results For Traceroute To 127.0.0.1")


class Nagios3Security(Nagios3Common):
    '''Nagios 3 security'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_CHANGE_commands(self):
        '''(Nagios3Security) Test CHANGE commands'''
        self._send_nagios_command("CHANGE_SVC_CHECK_COMMAND;localhost;HTTP;check_ssh")
        self._send_nagios_command("SCHEDULE_FORCED_SVC_CHECK;localhost;HTTP;1000000000")

        time.sleep(20)
        # This shouldn't have changed to "SSH OK", as CHANGE commands should be disabled
        # by the CVE-2008-5028 fix. A newer Nagios version may re-enable the CHANGE
        # commands and fix the problem another way though, so this will need to be
        # adapted to the newer way in the future.
        self._test_nagios_service("HTTP OK")

    def test_command_injection(self):
        '''(Nagios3Security) Test command injection'''
        # This should give an error message, as commands are now parsed for hidden
        # linefeeds by the CVE-2008-5027 fix.
        self._post_nagios_command("cmd_typ=3&cmd_mod=2&host=localhost&service=HTTP" \
                                  "&btnSubmit=Commit&com_author=Ubuntutest" \
                                  "&com_data=UbuntuRocks%0a%5b1229526917%5d%20DEL_SVC_COMMENT",
                                  regex = "An error occurred")

    def test_cve_2009_2288(self):
        '''(Nagios3Security) Test CVE-2009-2288'''
        magic_string = "UbuntuRocks"

        for command in ['ping', 'traceroute']:
            url = "nagios3/cgi-bin/statuswml.cgi?" + command + "=127.0.0.1%3Becho+" + magic_string

            report = self._test_nagios_url(url, "Invalid host name/ip")

            warning = 'The server returned "%s"!!!\n' % magic_string
            self.assertFalse(re.search(magic_string, report), warning + report)

    def test_cve_2011_1523(self):
        '''(Nagios3Security) Test CVE-2011-1523'''

        url = "nagios3/cgi-bin/statusmap.cgi?layer='onmouseover=\"alert('XSS')\"'"

        report = self._test_nagios_url(url, "Network Map For All Hosts", source=True)

        warning = 'The server returned the XSS!!!\n'
        self.assertFalse(re.search("onmouseover=\"alert\('XSS'\)\"", report), warning + report)

        warning = 'Could not find the escaped string!!!\n'
        self.assertTrue(re.search("onmouseover&#61;&#34;alert&#40;&#39;XSS&#39;&#41;&#34;", report), warning + report)

    def test_cve_2011_2179(self):
        '''(Nagios3Security) Test CVE-2011-2179'''

        if self.lsb_release['Release'] <= 10.10:
            return self._skipped("vulnerable function doesn't exist in Maverick and older")

        url = "nagios3/cgi-bin/config.cgi?type=command&expand=<script>alert(\"XSS\")</script>"

        report = self._test_nagios_url(url, "Configuration", source=True)

        warning = 'The server returned the XSS!!!\n'
        self.assertFalse(re.search("<script>alert\(\"XSS\"\)</script>", report), warning + report)

        warning = 'Could not find the escaped string!!!\n'
        self.assertTrue(re.search("&#60;script&#62;alert&#40;&#34;XSS&#34;&#41;&#60;&#47;script&#62;", report), warning + report)

    def test_cve_2012_6096(self):
        '''(Nagios3Security) Test CVE-2012-6096'''

        # Based on http://archives.neohapsis.com/archives/fulldisclosure/2012-12/0108.html

        long_string = 'a' * 4000
        url = "nagios3/cgi-bin/history.cgi?host=" + long_string

        report = self._test_nagios_url(url, "Host Alert History", source=True)

class Nagios3Stub(Nagios3Common):
    '''Stub tests'''
    def setUp(self):
        '''Generic test setup'''
        self._setUp()

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

    def test_stub(self):
        '''(Nagios3Stub) stub'''
        pass


if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()

    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios3Stub))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios3Generic))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios3Command))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios3CGI))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Nagios3Security))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
