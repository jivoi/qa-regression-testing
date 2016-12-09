#!/usr/bin/python
#
#    test-apparmor.py quality assurance test script for apparmor
#    Copyright (C) 2009-2014 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: apparmor apparmor-utils netcat sudo build-essential libapparmor-dev attr apport python-pexpect libpam-apparmor libgtk2.0-dev pyflakes apparmor-profiles quilt libdbus-1-dev
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: python-libapparmor:!lucid python3-libapparmor:!lucid python3-libapparmor:!precise apparmor-easyprof:!precise apparmor-easyprof:!quantal apparmor-easyprof:!lucid ruby1.9:!lucid ruby1.9:!precise ruby1.9:!saucy ruby1.8:lucid ruby1.8:precise
# files and directories required for the test to run:
# QRT-Depends: apparmor/
# QRT-Privilege: root

'''
    How to run against a clean VM named 'hardy':
        sudo sh -c 'apt-get -y install <QRT-Packages> && ./test-apparmor.py -v'

    NOTE:
    - The ApparmorTestsuites tests will 'apt-get source apparmor', build a
      local copy and then run the tests on this copy. This means that the
      version you want to test with this script must have apt-gettable sources.

    TODO:
    - aa-genprof
    - test for http://launchpad.net/bugs/331534
    - finish stress tests
    - pam_apparmor < 9.10
    - pam-apparmor for default_user in 9.10 when not using order=default,user,group
'''


import glob
import grp
import os
import pexpect
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import testlib

try:
    from private.qrt.Apparmor import PrivateApparmorTest
except ImportError:
    class PrivateApparmorTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

run_subdomain_stress = False
run_parser_stress = False

# Use the installed libapparmor for tests
os.environ['USE_SYSTEM']="1"

class ApparmorTest(testlib.TestlibCase, PrivateApparmorTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = ""
        self.profile = ""
        self.script = ""
        self.init = "/etc/init.d/apparmor"
        self.upstart = "/etc/init/apparmor.conf"
        self.touch = "/usr/bin/touch"
        if self.lsb_release['Release'] < 10.04:
            self.touch = "/bin/touch"

        self._start()

        self.repository_conf = "/etc/apparmor/repository.conf"

        self.disabled_profiles = []

        # Drop DISPLAY to keep apport from prompting the wrong place
        if 'DISPLAY' in os.environ:
            del os.environ['DISPLAY']

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None
        if self.profile != "":
            disable_profile = os.path.join("/etc/apparmor.d/disable", os.path.basename(self.profile))
            if os.path.exists(disable_profile):
                os.unlink(disable_profile)

            force_profile = os.path.join("/etc/apparmor.d/force-complain", os.path.basename(self.profile))
            if os.path.exists(force_profile):
                os.unlink(force_profile)

            if os.path.exists(self.profile):
                self._remove_profile(self.profile)
                os.unlink(self.profile)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        for p in self.disabled_profiles:
            bak = "%s.autotest" % p
            if os.path.exists(bak):
                shutil.move(bak, p)
                testlib.cmd(['apparmor_parser', '-R', "/etc/apparmor.d/%s" % os.path.basename(p)])

        testlib.config_restore(self.repository_conf)

    def _add_profile(self, profile=None, complain=False):
        '''Add an apparmor profile, creating a simple one if none specified.
	   Need to unload it yourself, or assign the return value to
           self.profile'''
        script = ''
        flags = ""
        if complain:
            flags = "flags=(complain)"
        if not profile:
            if self.tmpdir == "":
                self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
            script = os.path.join(self.tmpdir, "testme.sh")
            contents = '''#!/bin/bash
exit 0'''
            testlib.create_fill(script, contents, mode=0755)

            profile = os.path.join(self.tmpdir, "testme.profile")
            contents = '''#include <tunables/global>
%s %s {
  #include <abstractions/base>
  /bin/bash rix,
  %s r,
}''' % (script, flags, script)
            testlib.create_fill(profile, contents)

        rc, report = testlib.cmd(['apparmor_parser', '-a', profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        return profile, script

    def _remove_profile(self, profile):
        '''Remove apparmor profile'''
        testlib.cmd(['apparmor_parser', '-R', profile])

    def _get_number_enforcing(self):
        '''Get number of enforcing profiles'''
        rc, report = testlib.cmd(['aa-status', '--enforced'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        return int(report)

    def _get_number_complaining(self):
        '''Get number of complaining profiles'''
        rc, report = testlib.cmd(['aa-status', '--complaining'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        return int(report)

    def _find_binary(self, profile):
        '''Determine binaries of profile'''
        binaries = []
        for line in file(profile).read().splitlines():
            if line.strip().endswith('{'):
                binaries.append(line.strip().split()[0])

        return binaries

    def _is_loaded(self, profile):
        '''Check if profile is loaded'''
        binaries = self._find_binary(profile)

        rc, report = testlib.cmd(['aa-status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        number_loaded = 0
        for b in binaries:
            for line in report.splitlines():
                if line.endswith(b):
                    number_loaded += 1

        if len(binaries) == number_loaded:
            return True

        return False

    def _is_enforcing(self, profile):
        '''Check if profile is in enforcing mode'''
        self.assertTrue(self._is_loaded(profile), "'%s' is not loaded" % profile)
        binaries = self._find_binary(profile)

        rc, report = testlib.cmd(['aa-status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        number_enforcing = 0
        for b in binaries:
            in_enforce = False

            for line in report.splitlines():
                if "profiles are in enforce" in line:
                    in_enforce = True
                    continue
                elif "profiles are in complain mode" in line:
                    in_enforce = False
                    continue
                if line.endswith(b) and in_enforce:
                    number_enforcing += 1

        if len(binaries) == number_enforcing:
            return True

        return False

    def _is_init_systemd(self):
        '''detect systemd as init'''

        rc, report = testlib.cmd(['ps', 'hp1', '-ocomm'])
        if report.strip() == 'systemd':
            return True

        return False


    def _reload(self):
        '''Reload apparmor'''

        # detect systemd, will probably need to change behavior once
        # we get an apparnor systemd unit
        if self._is_init_systemd():
            rc, report = testlib.cmd(['systemctl', 'force-reload', 'apparmor'])
        elif os.path.exists(self.upstart):
            rc, report = testlib.cmd(['start', 'apparmor', 'ACTION=force-reload'])
        else:
            rc, report = testlib.cmd([self.init, 'force-reload'])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._is_enabled()

    def _start(self):
        '''start apparmor'''

        # detect systemd, will probably need to change behavior once
        # we get an apparnor systemd unit
        if self._is_init_systemd():
            rc, report = testlib.cmd(['systemctl', 'start', 'apparmor'])
        elif os.path.exists(self.upstart):
            rc, report = testlib.cmd(['start', 'apparmor'])
        else:
            rc, report = testlib.cmd([self.init, 'start'])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._is_enabled()

    def _is_enabled(self):
        '''Check if enabled'''
        rc, report = testlib.cmd(['aa-status', '--enabled'])
        expected = 0
        result = 'Got exit code %d, not %d\n' % (rc, expected)
        self.assertTrue(expected == rc, result + report)

    def test_kernel(self):
        '''Test kernel'''
        syspath = "/sys/module/apparmor/parameters/enabled"
        self.assertTrue(os.path.exists(syspath), "'%s' does not exist" % (syspath))
        rc, report = testlib.cmd(['egrep', '(Y|1)', syspath])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_aa_status(self):
        '''Test aa-status'''
        for arg in ['--enabled', '--complaining', '--enforced', '--profiled']:
            rc, report = testlib.cmd(['aa-status', arg])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def test_add_remove_profile(self):
        '''Test add/remove profile'''
        prev = self._get_number_enforcing()
        self.profile, self.script = self._add_profile()
        cur = self._get_number_enforcing()
        self.assertTrue(cur > prev, "%d <= %d" % (cur, prev))

        prev = cur
        self._remove_profile(self.profile)
        cur = self._get_number_enforcing()
        self.assertTrue(cur < prev, "%d >= %d" % (cur, prev))

        os.unlink(self.profile)

    def test_enforce(self):
        '''Test enforce profile'''
        # start in enforce
        self.profile, self.script = self._add_profile()
        contents = '''#!/bin/sh
set -e
%s %s/foo
''' % (self.touch, self.tmpdir)
        testlib.create_fill(self.script, contents, mode=0755)
        rc, report = testlib.cmd([self.script])
        unexpected = 0
        result = 'Unexpected exit code %d\n' % (rc)
        self.assertNotEquals(unexpected, rc, result + report)

    def test_complain(self):
        '''Test complain profile'''
        self.profile, self.script = self._add_profile(complain=True)
        contents = '''#!/bin/sh
set -e
%s %s/foo
''' % (self.touch, self.tmpdir)
        testlib.create_fill(self.script, contents, mode=0755)
        rc, report = testlib.cmd([self.script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_enforce_and_complain(self):
        '''Test moving from enforce to complain and back'''
        # start in enforce
        self.profile, self.script = self._add_profile()
        contents = '''#!/bin/sh
set -e
%s %s/foo
''' % (self.touch, self.tmpdir)
        testlib.create_fill(self.script, contents, mode=0755)
        rc, report = testlib.cmd([self.script])
        unexpected = 0
        result = 'Unexpected exit code %d\n' % (rc)
        self.assertNotEquals(unexpected, rc, result + report)

        # move to complain
        rc, report = testlib.cmd(['apparmor_parser', '-C', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        rc, report = testlib.cmd([self.script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # move back to enforce
        rc, report = testlib.cmd(['apparmor_parser', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        rc, report = testlib.cmd([self.script])

        unexpected = 0
        result = 'Unexpected exit code %d\n' % (rc)
        self.assertNotEquals(unexpected, rc, result + report)

        # move to complain
        rc, report = testlib.cmd(['apparmor_parser', '-C', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        rc, report = testlib.cmd([self.script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_aa_disable_and_aa_enforce(self):
        '''Test aa-disable'''
        if self.lsb_release['Release'] < 11.04:
            return self._skipped("aa-disable not available in 10.10 and earlier")
        self.profile, self.script = self._add_profile()
        contents = '''#!/bin/sh
set -e
%s %s/foo
''' % (self.touch, self.tmpdir)
        testlib.create_fill(self.script, contents, mode=0755)

        # move this into /etc/apparmor.d, otherwise aa-* don't work
        shutil.move(self.profile, "/etc/apparmor.d")
        self.profile = os.path.join("/etc/apparmor.d", os.path.basename(self.profile))
        disabled = os.path.join("/etc/apparmor.d/disable", os.path.basename(self.profile))

        # aa-* utils don't work right when the path doesn't match the profile
        # name
        for i in [ self.profile ]:
            rc, report = testlib.cmd(['aa-enforce', i])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertFalse(os.path.exists(disabled), "Found %s" % disabled)

            # is in enforce
            rc, report = testlib.cmd([self.script])
            unexpected = 0
            result = 'Unexpected exit code %d\n' % (rc)
            self.assertNotEquals(unexpected, rc, result + report)

            # disable the profile
            rc, report = testlib.cmd(['aa-disable', i])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(os.path.exists(disabled), "Could not find %s" % disabled)

            rc, report = testlib.cmd([self.script])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # move to enforce
            rc, report = testlib.cmd(['aa-enforce', i])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertFalse(os.path.exists(disabled), "Found %s" % disabled)

            rc, report = testlib.cmd([self.script])
            unexpected = 0
            result = 'Unexpected exit code %d\n' % (rc)
            self.assertNotEquals(unexpected, rc, result + report)

    def test_aa_complain_and_aa_enforce(self):
        '''Test enforce to complain and back with aa-complain/aa-enforce'''
        self.profile, self.script = self._add_profile()
        contents = '''#!/bin/sh
set -e
%s %s/foo
''' % (self.touch, self.tmpdir)
        testlib.create_fill(self.script, contents, mode=0755)

        # move this into /etc/apparmor.d, otherwise aa-* don't work
        shutil.move(self.profile, "/etc/apparmor.d")
        self.profile = os.path.join("/etc/apparmor.d", os.path.basename(self.profile))
        rc, report = testlib.cmd(['apparmor_parser', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # still in enforce
        rc, report = testlib.cmd([self.script])
        unexpected = 0
        result = 'Unexpected exit code %d\n' % (rc)
        self.assertNotEquals(unexpected, rc, result + report)

        # move to complain
        rc, report = testlib.cmd(['aa-complain', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([self.script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # move to enforce
        rc, report = testlib.cmd(['aa-enforce', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([self.script])
        unexpected = 0
        result = 'Unexpected exit code %d\n' % (rc)
        self.assertNotEquals(unexpected, rc, result + report)

    def test_initscript(self):
        '''Test initscript'''

        if self._is_init_systemd():
            return self._skipped("Init is systemd")
        # Skip test if there's an upstart job
        elif os.path.exists(self.upstart):
            return self._skipped("Package has an upstart job")

        print ""
        cmd = 'stop'
        print " %s" % cmd
        if testlib.dpkg_compare_installed_version('apparmor', 'ge', '2.5.1~rc1'):
            rc, report = testlib.cmd([self.init, cmd])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd(['aa-status', '--enabled'])
            expected = 0
            result = 'Got exit code %d, not %d\n' % (rc, expected)
            self.assertTrue(expected == rc, result + report)

            num_cache = len(os.listdir("/etc/apparmor.d/cache"))
            expected = 0
            result = 'Found %d file(s) in /etc/apparmor.d/cache, expected %d\n' % (num_cache, expected)
            self.assertEquals(expected, num_cache, result + report)

            cmd = 'teardown'
            print " %s" % cmd

        rc, report = testlib.cmd([self.init, cmd])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['aa-status', '--enabled'])
        not_expected = 0
        result = 'Got unexpected exit code %d\n' % (rc)
        self.assertTrue(rc != not_expected, result + report)

        cmd = "status"
        rc, report = testlib.cmd([self.init, cmd])
        if self.lsb_release['Release'] < 10.04:
            print " %s" % cmd
            expected = 0
        else:
            print " %s (unloaded: LP: #654841)" % cmd
            expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for action in ['start', 'restart', 'reload', 'force-reload']:
            print " %s" % action
            rc, report = testlib.cmd([self.init, action])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._is_enabled()

        cmd = "status"
        print " %s (loaded)" % cmd
        rc, report = testlib.cmd([self.init, cmd])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if self.lsb_release['Release'] == 9.10:
            search = "(enforce)"
            result = "Could not find '%s' in report\n"
            self.assertTrue(search in report, result + report)
        else:
            search = "apparmor module is loaded"
            result = "Could not find '%s' in report\n"
            self.assertTrue(search in report, result + report)

    def test_upstart(self):
        '''Test upstart job'''

        # Skip test if there's no upstart job
        if not os.path.exists(self.upstart):
            return self._skipped("Package has no upstart job")
        # skip test is init is systemd
        elif self._is_init_systemd():
            return self._skipped("Init is systemd")

        print ""
        print " ACTION=clear"
        rc, report = testlib.cmd(['start', 'apparmor', 'ACTION=clear'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['aa-status', '--enabled'])
        expected = 0
        result = 'Got exit code %d, not %d\n' % (rc, expected)
        self.assertTrue(expected == rc, result + report)

        num_cache = len(os.listdir("/etc/apparmor.d/cache"))
        expected = 0
        result = 'Found %d file(s) in /etc/apparmor.d/cache, expected %d\n' % (num_cache, expected)
        self.assertEquals(expected, num_cache, result + report)

        print " ACTION=teardown"
        rc, report = testlib.cmd(['start', 'apparmor', 'ACTION=teardown'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['aa-status', '--enabled'])
        not_expected = 0
        result = 'Got unexpected exit code %d\n' % (rc)
        self.assertTrue(rc != not_expected, result + report)

        cmd = "status"
        rc, report = testlib.cmd([cmd, 'apparmor'])
        print " %s" % cmd
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for action in ['start', 'restart', 'reload', 'force-reload']:
            print " %s" % action

            expected = 0

            if action == 'start':
                rc, report = testlib.cmd([action, 'apparmor'])
            elif action == 'restart':
                rc, report = testlib.cmd([action, 'apparmor'])
                # Can't restart something that isn't running
                expected = 1
            else:
                rc, report = testlib.cmd(['start', 'apparmor',
                                          'ACTION=%s' % action])


            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._is_enabled()

    def test_dac_override(self):
        '''Test dac_override'''
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.script = os.path.join(self.tmpdir, "dac.sh")

        os.chmod(self.tmpdir, 0755)

        contents = '''#!/bin/dash
mkdir %s/foo 2>/dev/null || true
echo stuff > %s/foo/bar
''' % (self.tmpdir, self.tmpdir)
        testlib.create_fill(self.script, contents, mode=0755)

        profile_no_dac = os.path.join(self.tmpdir, "profile_no_dac")
        contents = '''#include <tunables/global>
%s {
  #include <abstractions/base>
  /bin/dash rix,
  /bin/mkdir rix,
  %s/dac.sh r,
  %s/ rw,
  %s/foo/ rw,
  %s/foo/** rw,
}''' % (self.script, self.tmpdir, self.tmpdir, self.tmpdir, self.tmpdir)
        testlib.create_fill(profile_no_dac, contents)

        profile_dac = os.path.join(self.tmpdir, "profile_dac")
        contents = '''#include <tunables/global>
%s {
  #include <abstractions/base>
  capability dac_override,
  /bin/dash rix,
  /bin/mkdir rix,
  %s/dac.sh r,
  %s/ rw,
  %s/foo/ rw,
  %s/foo/** rw,
}''' % (self.script, self.tmpdir, self.tmpdir, self.tmpdir, self.tmpdir)
        testlib.create_fill(profile_dac, contents)

        profile_dac_noaccess = os.path.join(self.tmpdir, "profile_dac_noaccess")
        contents = '''#include <tunables/global>
%s {
  #include <abstractions/base>
  capability dac_override,
  /bin/dash rix,
  /bin/mkdir rix,
  %s/dac.sh r,
  %s/foo/ rw,
}''' % (self.script, self.tmpdir, self.tmpdir)
        testlib.create_fill(profile_dac_noaccess, contents)

        for p in [ profile_no_dac, profile_dac, profile_dac_noaccess]:
            rc, report = testlib.cmd(['apparmor_parser', '-r', p])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self._is_enforcing(p), "'%s' not in enforcing mode" % self.profile)

            foodir = os.path.join(self.tmpdir, "foo")
            if os.path.exists(foodir):
                testlib.recursive_rm(foodir)

            os.mkdir(foodir)
            os.chown(foodir, self.user.uid, self.user.gid)

            rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'touch', os.path.join(foodir, "bar")])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # can we write to foo/bar when it is 644 as regular user?
            os.chmod(os.path.join(foodir, "bar"), 0644)
            time.sleep(3)
            expected = 0
            if p == profile_dac_noaccess:
                expected = 2
            rc, report = testlib.cmd(['sudo', '-u', self.user.login, self.script])
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, p)
            self.assertEquals(expected, rc, result + report)

            # can we write to foo/bar when it is 000 as regular user?
            os.chmod(os.path.join(foodir, "bar"), 0000)
            time.sleep(3)
            expected = 2
            rc, report = testlib.cmd(['sudo', '-u', self.user.login, self.script])
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, p)
            self.assertEquals(expected, rc, result + report)

            # can we write to foo/bar when it is 000 as root?
            expected = 2
            if p == profile_dac:
                expected = 0
            rc, report = testlib.cmd(self.script)
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, p)
            self.assertEquals(expected, rc, result + report)

    def test_ubuntu_disable(self):
        '''Test /etc/apparmor.d/disable'''
        self._is_enabled()

        # create a profile and add it to /etc/apparmor.d
        self.profile, self.script = self._add_profile()
        shutil.move(self.profile, "/etc/apparmor.d")
        self.profile = os.path.join("/etc/apparmor.d", os.path.basename(self.profile))
        rc, report = testlib.cmd(['apparmor_parser', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self._is_enforcing(self.profile), "'%s' not in enforcing mode" % self.profile)

        # create the disable symlink
        disable_profile = os.path.join("/etc/apparmor.d/disable", os.path.basename(self.profile))
        self.assertFalse(os.path.exists(disable_profile), "'%s' already exists" % disable_profile)

        rc, report = testlib.cmd(['ln', '-s', self.profile, disable_profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._reload()
        self.assertFalse(self._is_loaded(self.profile), "'%s' is loaded" % self.profile)

    def test_ubuntu_disabled_profiles(self):
        '''Test profiles in /etc/apparmor.d/disable/*'''
        if not os.path.isdir('/etc/apparmor.d/disable'):
            return self._skipped("apparmor does not support the disable directory in this release")
        self._is_enabled()

        self.disabled_profiles = glob.glob('/etc/apparmor.d/disable/*')
        print ""
        for p in self.disabled_profiles:
            print " %s" % p
            shutil.move(p, "%s.autotest" % p)
            rc, report = testlib.cmd(['aa-enforce', os.path.join('/etc/apparmor.d', os.path.basename(p))])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def test_ubuntu_force_complain(self):
        '''Test /etc/apparmor.d/force-complain'''
        self._is_enabled()

        # create a profile and add it to /etc/apparmor.d
        self.profile, self.script = self._add_profile()
        shutil.move(self.profile, "/etc/apparmor.d")
        self.profile = os.path.join("/etc/apparmor.d", os.path.basename(self.profile))
        rc, report = testlib.cmd(['apparmor_parser', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self._is_enforcing(self.profile), "'%s' is not in enforcing mode" % self.profile)

        # create the disable symlink
        force_profile = os.path.join("/etc/apparmor.d/force-complain", os.path.basename(self.profile))
        self.assertFalse(os.path.exists(force_profile), "'%s' already exists" % force_profile)

        rc, report = testlib.cmd(['ln', '-s', self.profile, force_profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._reload()
        self.assertFalse(self._is_enforcing(self.profile), "'%s' is in enforcing mode" % self.profile)

    def test_aa_unconfined(self):
        '''Test aa-unconfined'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec /bin/nc -l 65001 >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)
        rc, report = testlib.cmd(['aa-unconfined'])

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Could not find /bin/nc* in report\n"
        self.assertTrue(re.search('[1-9][0-9]* /bin/nc(.openbsd|.traditional)( \(/bin/nc\))? not confined', report), result + report)

    def _test_logprof(self, log_contents, expected_rc, unexpected_output):
        '''Test aa-logprof'''
        contents = '''[repository]
  enabled = no
'''
        testlib.config_replace(self.repository_conf, contents)

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        log = os.path.join(self.tmpdir, "testlib.log")
        testlib.create_fill(log, log_contents, mode=0644)

        rc, report = testlib.cmd(['aa-logprof', '-f', log])
        result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
        self.assertEquals(expected_rc, rc, result + report)
        self.assertFalse(unexpected_output in report, "Found '%s' in report:\n%s" % (unexpected_output, report))

    def test_lp652674(self):
        '''Test aa-logprof LP: #652674'''
        log_contents='Oct 14 07:14:13 bug652674 kernel: [    5.429706] type=1400 audit(1287058453.835:9): apparmor="STATUS" operation="profile_load" name="/usr/share/gdm/guest-session/Xsession" pid=1201 comm="apparmor_parser"\n'
        self._test_logprof(log_contents, 0, 'SubDomain.pm')

    def test_lp1243932_send(self):
        '''Test aa-logprof LP: #1243932 for send mode'''
        if self.lsb_release['Release'] < 13.10:
            return self._skipped("dbus mediation not supported before 13.10")
        log_contents='Jul 31 17:10:35 host dbus[1692]: apparmor="DENIED" operation="dbus_method_call"  bus="session" name="org.freedesktop.DBus" path="/org/freedesktop/DBus" interface="org.freedesktop.DBus" member="Hello" mask="send" pid=2922 profile="/usr/bin/dbus_service" peer_profile="unconfined"\n'
        self._test_logprof(log_contents, 0, 'Log contains unknown mode')

    def test_lp1243932_receive(self):
        '''Test aa-logprof LP: #1243932 for receive mode'''
        if self.lsb_release['Release'] < 13.10:
            return self._skipped("dbus mediation not supported before 13.10")
        log_contents='Jul 31 17:11:58 host dbus[1692]: apparmor="DENIED" operation="dbus_signal"  bus="session" name="com.apparmor.Test" path="/com/apparmor/Test" interface="com.apparmor.Test" member="Signal" mask="receive" pid=2945 profile="/usr/bin/dbus_service" peer_pid=2947 peer_profile="unconfined"\n'
        self._test_logprof(log_contents, 0, 'Log contains unknown mode')

    def test_lp1243932_bind(self):
        '''Test aa-logprof LP: #1243932 for bind mode'''
        if self.lsb_release['Release'] < 13.10:
            return self._skipped("dbus mediation not supported before 13.10")
        log_contents='Jul 31 17:11:16 host dbus[1692]: apparmor="DENIED" operation="dbus_bind"  bus="session" name="com.apparmor.Test" mask="bind" pid=2940 profile="/usr/bin/dbus_service"\n'
        self._test_logprof(log_contents, 0, 'Log contains unknown mode')

    def test_lp1231778(self):
        '''Test apparmor_parser LP: #1231778'''
        if self.lsb_release['Release'] < 13.10:
            return self._skipped("dbus rules were not supported before 13.10")
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        profile = os.path.join(self.tmpdir, "lp1231778.profile")
        contents = 'profile lp1231778 { dbus, }\n'
        testlib.create_fill(profile, contents)

        # 13.10 and newer parsers should always accept dbus rules but they may
        # be ignored
        rc, report = testlib.cmd(['apparmor_parser', '-a', profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Let tearDown unload the profile
        self.profile = profile

        # Now ensure that dbus rules were ignored, with a warning, if the
        # kernel doesn't have a dbus features file
        if not os.path.exists("/sys/kernel/security/apparmor/features/dbus/mask"):
            search = 'dbus rules not enforced'
            self.assertTrue(search in report, "Did not find '%s' in report:\n%s" % (search, report))

    def test_env_scrub(self):
        '''Test scrubbing'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        exe = os.path.join(self.tmpdir, "exe")
        exe_c = exe + ".c"

        exe2 = os.path.join(self.tmpdir, "exe2")
        exe2_c = exe2 + ".c"

        test_str = "testlib_string"
        test_ld_lib = os.path.join(self.tmpdir, test_str)
        test_ld_lib_c = test_ld_lib + ".c"

        test_exes = dict()
        test_modes = ['ux', 'Ux', 'px', 'Px', 'ix']
        if self.lsb_release['Release'] >= 10.04:
            test_modes += ['cx', 'Cx']
        for i in test_modes:
            test_exes[i] = os.path.join(self.tmpdir, i)

        test_scrub_envs = ['LD_PRELOAD', 'LD_LIBRARY_PATH']
        test_untouched_envs = ['TESTLIBSET']
        test_unset_envs = ['TESTLIBNOTSET']

        self.profile = os.path.join(self.tmpdir, "profile")

	# Create the profile application, which sets some env variables to test
        contents = '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <libgen.h>

int main(int argc, char * argv[])
{
    char *dname_exe;
    char *dname;
    char *args[2];
    pid_t child;

    /* rudimentary error checking */
    if (argc < 2) {
        fprintf(stderr,"Usage: %s <path>\\n", argv[0]);
        exit(1);
    }
    if (access(argv[1], R_OK|X_OK) != 0) {
        perror("access failed");
        exit(1);
    }

    dname_exe = dirname(strdup(argv[0]));
    dname = dirname(strdup(argv[1]));
    /* Allow execute of anything in the same directory as this executable */
    if (strcmp(dname_exe, dname) != 0) {
        fprintf(stderr,"%s != %s\\n", dname_exe, dname);
        exit(1);
    }
'''
        for i in test_scrub_envs + test_untouched_envs:
            val = test_str
            if i == "LD_LIBRARY_PATH":
                val = self.tmpdir
            contents += '    setenv("%s", "%s", 1);\n' % (i, val)

        contents += '''
    args[0] = argv[1];
    args[1] = 0x0;
    printf ("%s:\\n", args[0]);
    execv(args[0], args);
    perror("exec failed");
    exit(1);
}
'''
        testlib.create_fill(exe_c, contents)

        rc, report = testlib.cmd(['gcc', '-o', exe, exe_c])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Create an executable to output the environment to test
        contents = '''
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>

int main(int argc, char * argv[])
{
'''
        for i in test_scrub_envs + test_untouched_envs + test_unset_envs:
            contents += '    printf ("%s=%%s\\n", getenv("%s"));\n' % (i, i)

        contents += '''
    return 0;
}
'''
        testlib.create_fill(exe2_c, contents)

        rc, report = testlib.cmd(['gcc', '-o', exe2, exe2_c])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Create the various executables to test by hardlinking to exe2
        for k in test_exes.keys():
            os.link(exe2, test_exes[k])

        # Create the LD_PRELOAD shared library
        contents = '''
int __attribute__((constructor)) testlib_func(){
    return 0;
}
'''
        testlib.create_fill(test_ld_lib_c, contents)

        rc, report = testlib.cmd(['gcc', '-shared', '-fPIC', '-o', test_ld_lib, test_ld_lib_c])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Create the profile for the executable
        contents = '''
#include <tunables/global>
%s {
  #include <abstractions/base>
  %s mr,
''' % (exe, test_ld_lib)
        for k in test_exes.keys():
            perms = k
            if self.lsb_release['Release'] < 10.04:
                perms += 'r'
            if k.startswith('c') or k.startswith('C'):
                contents += "  %s %s -> %s_exe,\n" % (test_exes[k], perms, k)
            else:
                contents += "  %s %s,\n" % (test_exes[k], perms)

        if self.lsb_release['Release'] >= 10.04:
            for k in ['Cx', 'cx']:
                contents += '''
  profile %s_exe {
    #include <abstractions/base>
    # for file_mprotect
    %s r,
    %s mr,
  }
''' % (k, test_exes[k], test_ld_lib)

        contents += '}\n'

        for k in ['Px', 'px']:
            exe_perms = 'r'
            if self.lsb_release['Release'] < 10.04:
                exe_perms = 'mr'
            contents += '''
%s {
  #include <abstractions/base>
  # for file_mprotect
  %s %s,
  %s mr,
}
''' % (test_exes[k], test_exes[k], exe_perms, test_ld_lib)

        testlib.create_fill(self.profile, contents)
        self._add_profile(profile=self.profile)

        print ""
        for k in test_exes.keys():
            print "  %s" % k
            rc, report = testlib.cmd([exe, test_exes[k]])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            for i in test_unset_envs:
                # these should not be set
                search = "%s=(null)" % i
                result = "Could not find '%s' in report:\n" % (search)
                self.assertTrue(search in report, result + report)

            for i in test_untouched_envs:
                # these should not be set
                search = "%s=%s" % (i, test_str)
                result = "Could not find '%s' in report:\n" % (search)
                self.assertTrue(search in report, result + report)

            for i in test_scrub_envs:
                val = test_str
                if i == "LD_LIBRARY_PATH":
                    val = self.tmpdir

                if k[0].isupper():
                    # these should be scrubbed
                    search = "%s=(null)" % i
                else:
                    # these should not be scrubbed
                    search = "%s=%s" % (i, val)

                result = "Could not find '%s' in report (%s):\n" % (search, k)
                self.assertTrue(search in report, result + report)

                # While we explicitly allow 'mr' for our shared library, if
                # LD_LIBRARY_PATH is scrubbed, ld.so fails with:
                # ERROR: ld.so: object 'testlib_string' from LD_PRELOAD cannot be preloaded: ignored.
                # Check for this.
                search = "ERROR: ld.so: object"
                expected = False
                if k[0].isupper():
                    expected = True
                    result = "Could not find '%s' in report (%s):\n" % (search, k)
                else:
                    result = "Found '%s' in report (%s):\n" % (search, k)
                self.assertEquals(search in report, expected, result + report)

        # this should fail
        print "  %s" % os.path.basename(exe2)
        rc, report = testlib.cmd([exe, exe2])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_easyprof(self):
        '''Test aa-easyprof'''
        if self.lsb_release['Release'] < 12.04:
            return self._skipped("aa-easyprof not in 11.10 and earlier")

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        test_exe = "/opt/bin/foo/bin/Foo"
        test_template = "test-template"
        test_template_dir = os.path.join(self.tmpdir, "templates")
        test_policygroup = "test-policygroup"
        test_policygroups_dir = os.path.join(self.tmpdir, "policygroups")
        test_template_var = "@{APPNAME}=foo"
        test_abstractions = "authentication,python"
        test_readpath = "/some/where/ro/"
        test_writepath = "/some/where/rw/"
        test_author = "John Doe"
        test_copyright = "Copyright 2012 FooBar"
        test_comment = "Some comment"

        os.mkdir(test_template_dir, 0755)
        os.mkdir(test_policygroups_dir, 0755)

        sub_profile_name = "###PROFILEATTACH###"
        if self.lsb_release['Release'] <= 13.04:
            sub_profile_name = "###BINARY###"

        contents = '''# vim:syntax=apparmor
# %s
# AppArmor policy for ###NAME###
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

###VAR###

%s {
  #include <abstractions/base>

  ###ABSTRACTIONS###

  ###POLICYGROUPS###

  ###READS###

  ###WRITES###
}

''' % (test_template, sub_profile_name)
        open(os.path.join(test_template_dir, test_template), 'w').write(contents)

        contents = '''
# %s
#include <abstractions/gnome>
#include <abstractions/nameservice>
''' % (test_policygroup)
        open(os.path.join(test_policygroups_dir, test_policygroup), 'w').write(contents)

        rc, report = testlib.cmd(['/usr/bin/aa-easyprof',
                                  '--templates-dir=%s' % test_template_dir,
                                  '--policy-groups-dir=%s' % test_policygroups_dir,
                                  '--template=%s' % test_template,
                                  '--policy-groups=%s' % test_policygroup,
                                  '--template-var=%s' % test_template_var,
                                  '--abstractions=%s' % test_abstractions,
                                  '--read-path=%s' % test_readpath,
                                  '--write-path=%s' % test_writepath,
                                  '--author=%s' % test_author,
                                  '--copyright=%s' % test_copyright,
                                  '--comment=%s' % test_comment,
                                  test_exe])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for search in [test_template_var, test_author, test_copyright, test_comment]:
            # in 13.10, we undonditionally quote template variables
            if self.lsb_release['Release'] >= 13.10 and search == test_template_var:
                k, v = search.split('=')
                search = '%s="%s"' % (k, v)

            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result + report)

        # in 13.10, we undonditionally quote the profile name
        search = '"%s" {' % test_exe
        if self.lsb_release['Release'] < 13.10:
            search = "%s {" % test_exe
        result = "Could not find '%s' in report:\n%s" % (search, report)
        self.assertTrue(search in report, result + report)

        for a in test_abstractions.split(','):
            search = "#include <abstractions/%s>" % a
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result + report)

        perm = 'rk'
        if self.lsb_release['Release'] < 13.10:
            perm = 'r'

        for search in ['%s %s,' % (test_readpath, perm), '%s** %s,' % (test_readpath, perm)]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result + report)

        for search in ['%s rw' % test_writepath, '%s** rwk' % test_writepath]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result + report)

    def test_caching(self):
        '''Test caching'''
        profiles = glob.glob('/etc/apparmor.d/*')
        profiles.sort()
        for p in profiles:
            if not os.path.isfile(p):
                continue
            cache = os.path.join('/etc/apparmor.d/cache', os.path.basename(p))
            if os.path.exists(cache):
                os.unlink(cache)

            rc, report = testlib.cmd(['/sbin/apparmor_parser', '--write-cache', '--skip-kernel-load', '--', p])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            if "Skipping" in report:
                continue

            self.assertTrue(os.path.exists(cache), "Could not find '%s'" % cache)

    def test_caching_954469(self):
        '''Test recaching'''
        cache_dir = '/etc/apparmor.d/cache'
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("9.04 and lower does not suppoprt caching")

        self.assertTrue(os.path.isdir(cache_dir), "Could not find '%s'"% cache_dir)

        # Be sure the cache is up to date. The 'start' action is supposed to
        # recache only if the kernel features change. Running two times in a
        # row on the same kernel should mean the second time does not recache
        self._start()

        cached_profiles = glob.glob('%s/*' % cache_dir)
        cached_profiles.sort()

        orig = dict()
        for c in cached_profiles:
            if os.path.basename(c).startswith('.'): # .features
                continue
            orig[c] = os.stat(c)

        time.sleep(1)

        self._start()

        current = dict()
        for c in cached_profiles:
            if os.path.basename(c).startswith('.'): # .features
                continue
            current[c] = os.stat(c)

        for c in cached_profiles:
            self.assertEquals(orig[c].st_mtime, current[c].st_mtime, "Modification times do not match for '%s' (%s != %s)" % (c, orig[c].st_mtime, current[c].st_mtime))

    def test_extras(self):
        '''Test extras'''
        if not os.path.exists("/usr/share/doc/apparmor-profiles/extras"):
            return self._skipped("please install the apparmor-profiles package")

        extras = glob.glob('/usr/share/doc/apparmor-profiles/extras/*')
        extras.sort()

        print ""
        for extra in extras:
            if not os.path.isfile(extra):
                continue
            if os.path.basename(extra) == "README":
                continue

            print "  %s" % os.path.basename(extra)

            rc, report = testlib.cmd(['apparmor_parser', '-p', extra])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, extra)
            self.assertEquals(expected, rc, result + report)

    def test_abstractions(self):
        '''Test abstractions'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        abstractions = glob.glob('/etc/apparmor.d/abstractions/*')
        abstractions += glob.glob('/etc/apparmor.d/abstractions/ubuntu-browsers.d/*')
        abstractions.sort()

        print ""
        for a in abstractions:
            if not os.path.isfile(a):
                continue
            inc = re.sub(r'/etc/apparmor.d/', '', a)
            if inc == "abstractions/base":
                continue

            print "  %s" % inc

            profile = os.path.join(self.tmpdir, "testme.profile")
            contents = '''
#include <tunables/global>
/nonexistent {
  #include <abstractions/base>
  #include <%s>
}
''' % (inc)
            testlib.create_fill(profile, contents)

            rc, report = testlib.cmd(['apparmor_parser', '-p', profile])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, profile)
            self.assertEquals(expected, rc, result + report)
            os.unlink(profile)


class ApparmorApport(testlib.TestlibCase):
    '''Test apport.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.apport_hook = "/usr/share/apport/package-hooks/source_apparmor.py"
        self.apport_crashdb = "/etc/apport/crashdb.conf.d/apparmor-crashdb.conf"
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.apport_output = os.path.join(self.tmpdir, "testlib.apport")

	# Update the apport hook so we don't fail with 'not a genuine Ubuntu
        # package'. Somewhat fragile, but meh
        contents = '''
    report['ThirdParty'] = 'True'
    report['CrashDB'] = 'apparmor'
'''
        testlib.config_replace(self.apport_hook, contents, True)

        # Update the apport crashdb
        contents = '''apparmor = {
        'impl' : 'launchpad',
        'project' : 'apparmor',
        'bug_pattern_base' : None,
}
'''
        apport_crashdb_dir = os.path.dirname(self.apport_crashdb)
        if not os.path.exists(apport_crashdb_dir):
            os.mkdir(apport_crashdb_dir, 0755)
        testlib.create_fill(self.apport_crashdb, contents, mode=0644)

        self.user = None
        self.apport_required_groups = ['adm']

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.user != None:
            for g in self.apport_required_groups:
                testlib.cmd(['deluser', self.user.login, g])
            self.user = None

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        testlib.config_restore(self.apport_hook)
        if os.path.exists(self.apport_crashdb):
            os.unlink(self.apport_crashdb)

    def test_apport_hooks(self):
        '''Test required apport hooks'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("apport-bug does not support --save in 9.10 and earlier")
        # clear out DISPLAY to prevent apport prompts
        os.environ['DISPLAY'] = ""
        rc, report = testlib.cmd(['apport-bug', 'apparmor', '--save', self.apport_output])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        apport_info = open(self.apport_output).read()

        search_strings = [
             'ProblemType: Bug',
             'ApparmorPackages:',
             ' apparmor',
             ' apparmor-utils',
             ' libapparmor',
             ' libapparmor-dev',
             ' libapparmor-perl',
             ' apparmor-utils',
             ' apparmor-docs',
             ' apparmor-profiles',
             ' libapache2-mod-apparmor',
             ' libpam-apparmor',
             ' auditd',
             ' libaudit',
             'ApparmorStatusOutput:',
             ' loaded',
             ' in enforce mode',
             ' in complain mode',
             'KernLog:',
             'Package: apparmor',
             'ProcKernelCmdline: ',
             'ProcVersionSignature: ',
             'PstreeP:',
             'SourcePackage: apparmor',
            ]

        for s in search_strings:
            self.assertTrue(s in apport_info, "Could not find '%s' in '%s'; contents were:\n%s" % (s, self.apport_output, apport_info))

    # racy
    def _test_lp655529(self):
        '''Test apport LP: #655529'''
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("Won't Fix in 9.10 and earlier")
        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        for g in self.apport_required_groups:
            rc, report = testlib.cmd(['adduser', self.user.login, g])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        os.chmod(self.tmpdir, 0755)
        os.chown(self.tmpdir, self.user.uid, self.user.gid)

        child = pexpect.spawn('sudo -H -u %s apport-bug apparmor --save %s' % (self.user.login, self.apport_output))
        try:
            child.expect('.*password for.*', timeout=5)
            child.kill(0)
        except:
            # TODO: This test only sometimes works on 12.04, but manual test
            # show it works. Need to figure out why this isn't working any
            # more.
            self.assertTrue(False, "Not prompted for a password")


class ApparmorTestsuites(testlib.TestlibCase):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.init = "/etc/init.d/apparmor"
        self.upstart = "/etc/init/apparmor.conf"

        self.topdir = os.getcwd()
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.source = os.path.join("%s/source/%s" % (self.topdir, self.lsb_release['Codename']))

        self.downloaded_source = False

        self.orig_ptrace = None
        self.yama_ptrace_scope = "/proc/sys/kernel/yama/ptrace_scope"
        self.yama_ptrace_scope_sysctl = "kernel.yama.ptrace_scope"
        if os.path.exists(self.yama_ptrace_scope):
            self.orig_ptrace = file(self.yama_ptrace_scope).read().splitlines()[0]

        # detect systemd, will probably need to change behavior once
        # we get an apparnor systemd unit
        self.running_systemd = False
        rc, report = testlib.cmd(['ps', '-p1', '-h', '-ocomm'])
        if report.strip() == 'systemd':
            self.running_systemd = True

        if self.running_systemd:
            rc, report = testlib.cmd(['systemctl', 'start', 'apparmor'])
        elif os.path.exists(self.upstart):
            rc, report = testlib.cmd(['start', 'apparmor'])
        else:
            rc, report = testlib.cmd([self.init, 'start'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.topdir)

        if self.orig_ptrace != None:
            testlib.cmd(['sysctl', '-w', "%s=%s" % (self.yama_ptrace_scope_sysctl, self.orig_ptrace)])

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _prepare_source(self):
        '''Fetches the source if needed and cd's into the toplevel source'''
        self.install_builddeps('apparmor')
        srcdir = os.path.join(self.tmpdir, "source/%s" % self.lsb_release['Codename'])
        if os.path.exists(self.source):
            os.mkdir(os.path.dirname(srcdir))
            shutil.copytree(self.source, srcdir)
            os.chdir(srcdir)
        else:
            os.makedirs(srcdir)
            os.chdir(srcdir)
            self.assertShellExitEquals(0,['apt-get','source','--allow-unauthenticated','apparmor'])
            shutil.copytree(os.path.dirname(srcdir), os.path.dirname(self.source))
            with open(os.path.join(self.source, '.downloaded_source'), 'w') as f:
                f.write('True')
        os.chdir(glob.glob('apparmor-*')[0])
        print "\n  preparing %s..." % os.path.basename(glob.glob('../apparmor*dsc')[0]),
        sys.stdout.flush()

        if self.lsb_release['Release'] >= 10.04:
            os.environ["QUILT_PATCHES"] = "debian/patches"
            testlib.cmd(['quilt', 'pop', '-a'])
            self.assertShellExitEquals(0,['quilt', 'push', '-a'])

            # add patch to compensate for LP: #105043
            if self.lsb_release['Release'] < 12.10 and self.lsb_release['Release'] > 10.04:
                patch = self.topdir + '/apparmor/patches/coredump_tests-' + self.lsb_release['Codename'] + '.patch'
                self.assertShellExitEquals(0, ['quilt', 'import', patch])
                self.assertShellExitEquals(0, ['quilt', 'push'])
            if self.lsb_release['Release'] < 13.04 and self.lsb_release['Release'] > 10.04:
                self.assertShellExitEquals(0, ['quilt', 'import',
                        self.topdir + '/apparmor/patches/clone_test-define_pagesize.patch'])
                self.assertShellExitEquals(0, ['quilt', 'push'])
            if self.lsb_release['Release'] < 13.04 and self.lsb_release['Release'] > 8.04:
                self.assertShellExitEquals(0, ['quilt', 'import',
                        self.topdir + '/apparmor/patches/apparmor-parser_caching_test.patch'])
                self.assertShellExitEquals(0, ['quilt', 'push'])
            # add patch to compensate for LP: #1470985
            if self.lsb_release['Release'] > 10.04 and self.lsb_release['Release'] < 15.10:
                self.assertShellExitEquals(0, ['quilt', 'import',
                        self.topdir + '/apparmor/patches/tests-convert_ptrace_getregset.patch'])
                self.assertShellExitEquals(0, ['quilt', 'push'])
            if self.lsb_release['Release'] == 16.04 or self.lsb_release['Release'] == 16.10:
                # Create the empty file that was meant to be created by
                # r3498-r3499-ignore-net-events-that-look-like-file-events.patch.
                # Quilt does not support creating new empty files.
                #
                # This file is created by the apparmor package's
                # debian/rules dh_auto_build target but, because
                # test-apparmor.py calls `make check` directly without
                # using the debian/rules targets, we must do it here too.
                empty_file = 'libraries/libapparmor/testsuite/test_multi/testcase_network_send_receive.err'
                open(empty_file, 'w').close()

        print("done")

    def test_zz_cleanup_source_tree(self):
        '''Cleanup downloaded source'''
        topsrc = os.path.dirname(self.source)
        if os.path.exists(topsrc) and os.path.exists(os.path.join(self.source, '.downloaded_source')):
            testlib.recursive_rm(topsrc)

    def test_regression_testsuite(self):
        '''Run kernel regression tests'''
        self._prepare_source()
        if os.path.exists('./tests/regression/subdomain'):
            os.chdir("./tests/regression/subdomain")
        else:
            os.chdir("./tests/regression/apparmor")
        rc, report = testlib.cmd(['make'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        failed_ok = []

        if self.lsb_release['Release'] < 12.04:
	    # These are racy and may depend on configuration in 11.10 and
            # earlier (though 11.10 seemed to hit it less often)
            failed_ok.append("Error: pwrite passed. Test 'PWRITE without w' was expected to 'fail'")
            failed_ok.append("Error: pwrite passed. Test 'PREAD without r' was expected to 'fail'")
            failed_ok.append("Error: rw passed. Test 'READ/WRITE fail' was expected to 'fail'")
        if self.lsb_release['Release'] < 11.10:
            # This should be fixed up in 2.5.2 and Lucid and Maverick SRUs
            failed_ok.append("Error: unix_fd_server failed. Test 'fd passing; confined client w/ w only' was expected to 'pass'.")

        # Disable ptrace protections if they are present, since this test needs
        # to be able to ptrace.
        if os.path.exists(self.yama_ptrace_scope):
            print "\n (disabling ptrace for this test)"
            rc, report = testlib.cmd(['sysctl', '-w', "%s=0" % (self.yama_ptrace_scope_sysctl)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['make', 'tests'])
        expected = 0
        # AppArmor 2.6 on Natty actually exits non-zero if tests fail, and
        # since we have 3 expected failures (above), we need to do this
        if self.lsb_release['Release'] == 11.04:
            expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

	# The testsuite does not exit with error on failure, so we check
        # against expected failures.
        found_error = False
        for line in report.splitlines():
            if line.startswith("Error:") or line.startswith("Fatal Error:"):
                err = True
                for ok_errs in failed_ok:
                    if line.startswith(ok_errs):
                        err = False
                        break
                if err:
                    found_error = True

        self.assertFalse(found_error, report)

    def test_utils_testsuite(self):
        '''Run utils (make check)'''
        if self.lsb_release['Release'] < 12.04:
            return self._skipped("'make check' not in 11.10 and earlier")
        self._prepare_source()
        os.chdir("./utils")

        rc, report = testlib.cmd(['make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_utils_testsuite3(self):
        '''Run utils (make check with python3)'''
        if self.lsb_release['Release'] < 12.10:
            return self._skipped("'make check for python3' not in 12.04 and earlier")
        self._prepare_source()
        os.chdir("./utils")

        # backup python values if they are set
        pvars = dict()
        for i in ['PYTHON', 'PYTHON_VERSIONS', 'PYTHON_VERSION']:
            if i in os.environ:
                pvars[i] = os.environ[i]
        os.environ['PYTHON'] = '/usr/bin/python3'
        os.environ['PYTHON_VERSION'] = '3'
        os.environ['PYTHON_VERSIONS'] = 'python3'

        rc, report = testlib.cmd(['make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # restore previous values
        for k in ['PYTHON', 'PYTHON_VERSIONS', 'PYTHON_VERSION']:
            if k in pvars:
                os.environ[k] = pvars[k]

    def test_parser_testsuite(self):
        '''Run parser regression tests'''
        self._prepare_source()
        os.chdir("./parser/tst")
        rc, report = testlib.cmd(['make'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['make', 'tests'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "Result: PASS"
        if self.lsb_release['Release'] < 10.04:
            search = "All tests successful"
        self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

    def _configure_libapparmor(self):
        '''Run ./configure for libapparmor'''
        target = 'override_dh_auto_configure'
        if self.lsb_release['Release'] < 14.04:
            target = 'configure'
        rc, report = testlib.cmd(['./debian/rules', target])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_libapparmor_testsuite(self):
        '''Run libapparmor testsuite'''
        self._prepare_source()
        self._configure_libapparmor()

        os.chdir("libraries/libapparmor")
        rc, report = testlib.cmd(['make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        #print report

    def test_libapparmor_testsuite3(self):
        '''Run libapparmor testsuite (with python3)'''
        if self.lsb_release['Release'] < 12.10:
            return self._skipped("'make check for python3' not in 12.04 and earlier")
        # backup python values if they are set
        pvars = dict()
        for i in ['PYTHON', 'PYTHON_VERSIONS', 'PYTHON_VERSION']:
            if i in os.environ:
                pvars[i] = os.environ[i]
        os.environ['PYTHON'] = '/usr/bin/python3'
        os.environ['PYTHON_VERSION'] = '3'
        os.environ['PYTHON_VERSIONS'] = 'python3'

        self._prepare_source()
        self._configure_libapparmor()

        os.chdir("libraries/libapparmor")
        rc, report = testlib.cmd(['make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # restore previous values
        for k in ['PYTHON', 'PYTHON_VERSIONS', 'PYTHON_VERSION']:
            if k in pvars:
                os.environ[k] = pvars[k]

    def test_stress_parser_testsuite(self):
        '''Run parser stress test'''
        global run_parser_stress
        if not run_parser_stress:
            return self._skipped("use --with-parser-stress to enable")
        if self.lsb_release['Release'] == 9.10:
            return self._skipped("parser stress tests are broken in 9.10")
        self._prepare_source()
        os.chdir("./tests/stress/parser")
        if self.lsb_release['Release'] < 14.04:
            subprocess.call(['sed', '-i', 's#/usr/bin/env ruby#/usr/bin/env ruby1.8#g', './stress.rb'])
        else:
            subprocess.call(['sed', '-i', 's#/usr/bin/env ruby#/usr/bin/env ruby1.9#g', './stress.rb'])

        rc, report = testlib.cmd(['./stress.sh'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        print report

    def test_stress_subdomain_testsuite(self):
        '''Run subdomain stress test'''
        global run_subdomain_stress
        if not run_subdomain_stress:
            return self._skipped("use --with-subdomain-stress to enable")
        self._prepare_source()
        os.chdir("tests/stress/subdomain")

        rc, report = testlib.cmd(['make', 'all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        print report

        print ""
        for t in ['change_hat', 'child', 'kill.sh', 'open', 's.sh', 'stress.sh']:
            print "  %s" % t
            if t == "change_hat":
                self._skipped("TODO: 512M is not enough")
                continue
            rc, report = testlib.cmd([os.path.join('./', t)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            print report

class ApparmorPAM(testlib.TestlibCase):
    '''Test PAM.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.pam_su = "/etc/pam.d/su"

        self.default_user = testlib.TestUser()
        self.confined_user = testlib.TestUser()
        self.confined_group = testlib.TestUser()
        self.unconfined_user = testlib.TestUser()
        self.unconfined_group = testlib.TestUser()
        self.adm_group = testlib.TestUser()
        rc, report = testlib.cmd(['usermod', '-g', 'adm', self.adm_group.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0755)

        self.default_user_fn = os.path.join(self.tmpdir, 'default_user')
        self.confined_user_fn = os.path.join(self.tmpdir, 'confined_user')
        self.confined_group_fn = os.path.join(self.tmpdir, 'confined_group')
        self.unconfined_user_fn = os.path.join(self.tmpdir, 'unconfined_user')
        self.unconfined_group_fn = os.path.join(self.tmpdir, 'unconfined_group')
        self.adm_group_fn = os.path.join(self.tmpdir, 'adm_group')

        self.check_string = "you read me"
        for f in [ self.default_user_fn, self.confined_user_fn,
                   self.confined_group_fn, self.unconfined_user_fn,
                   self.unconfined_group_fn, self.adm_group_fn ]:
            testlib.create_fill(f, self.check_string, mode=0644)

        self.pam_apparmor_policy = os.path.join("/etc/apparmor.d", "testlib-pam-apparmor")

        # AppArmor configuration
        #
        # IMPORTANT: as of AppArmor 2.5 only primary groups are checked
        #
        # When 'user' is searched first, we transition to confined_user. If
        # 'group' is searched first, we transition to 'adm_group'. As such,
        # adjust so that when 'user' is first, adm_group user can access
        # confined_user's files, but not adm_group's and vice versa when
        # 'group' is first. If 'default' is searched first, we transition
        # to DEFAULT unconditionally.
        contents = '''
#include <tunables/global>
/bin/su {
   #include <abstractions/authentication>
   #include <abstractions/base>
   #include <abstractions/nameservice>

   capability chown,
   capability setgid,
   capability setuid,
   capability audit_write,

   owner /etc/environment r,
   owner /etc/shells r,
   owner /etc/default/locale r,
   owner @{HOMEDIRS}/*/.Xauthority rw,
   owner @{HOMEDIRS}/*/.Xauthority-c w,
   owner @{HOMEDIRS}/*/.Xauthority-l w,
   @{HOME}/.xauth* rw,
   owner /proc/sys/kernel/ngroups_max r,
   /usr/bin/xauth rix,
   owner /{var/,}run/utmp rwk,
   owner @{PROC}/[1-9]*/loginuid r,

   # our hats
   ^DEFAULT {
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Px -> default_user,
     /bin/{c,k,tc}sh Px -> default_user,
   }
   ^%s {
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Px -> confined_user,
     /bin/{c,k,tc}sh Px -> confined_user,
   }
   ^%s {
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Px -> confined_group,
     /bin/{c,k,tc}sh Px -> confined_group,
   }
   ^%s {
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Ux,
     /bin/{c,k,tc}sh Ux,
   }
   ^%s {
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Ux,
     /bin/{c,k,tc}sh Ux,
   }
   ^%s {
     # This user has primary group of 'adm'
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Px -> confined_user,
     /bin/{c,k,tc}sh Px -> confined_user,
   }
   ^adm {
     # Users with primary group of 'adm'
     #include <abstractions/authentication>
     #include <abstractions/nameservice>

     capability dac_override,
     capability setgid,
     capability setuid,
     capability audit_write,

     /etc/default/su r,
     /etc/environment r,
     @{HOMEDIRS}/.xauth* w,

     /bin/{,b,d,rb}ash Px -> adm_group,
     /bin/{c,k,tc}sh Px -> adm_group,
   }
}

# our policy
profile default_user {
   #include <abstractions/base>
   #include <abstractions/bash>
   #include <abstractions/consoles>
   #include <abstractions/nameservice>

   deny capability sys_ptrace,

   owner /** rkl,
   @{PROC}/** r,

   /bin/**  Pixmr,
   /usr/bin/** Pixmr,
   owner @{HOMEDIRS}/ w,
   owner @{HOMEDIRS}/** w,

   %s r,
}

profile confined_user {
   #include <abstractions/base>
   #include <abstractions/bash>
   #include <abstractions/consoles>
   #include <abstractions/nameservice>

   deny capability sys_ptrace,

   owner /** rkl,
   @{PROC}/** r,

   /bin/**  Pixmr,
   /usr/bin/** Pixmr,
   owner @{HOMEDIRS}/ w,
   owner @{HOMEDIRS}/** w,

   %s r,
}

profile confined_group {
   #include <abstractions/base>
   #include <abstractions/bash>
   #include <abstractions/consoles>
   #include <abstractions/nameservice>

   deny capability sys_ptrace,

   owner /** rkl,
   @{PROC}/** r,

   /bin/**  Pixmr,
   /usr/bin/** Pixmr,
   owner @{HOMEDIRS}/ w,
   owner @{HOMEDIRS}/** w,

   %s r,
}

profile adm_group {
   #include <abstractions/base>
   #include <abstractions/bash>
   #include <abstractions/consoles>
   #include <abstractions/nameservice>

   deny capability sys_ptrace,

   owner /** rkl,
   @{PROC}/** r,

   /bin/**  Pixmr,
   /usr/bin/** Pixmr,
   owner @{HOMEDIRS}/ w,
   owner @{HOMEDIRS}/** w,

   %s r,
}
''' % (self.confined_user.login, grp.getgrgid(self.confined_group.gid)[0], self.unconfined_user.login, grp.getgrgid(self.unconfined_group.gid)[0], self.adm_group.login, self.default_user_fn, self.confined_user_fn, self.confined_group_fn, self.adm_group_fn)

        testlib.create_fill(self.pam_apparmor_policy, contents, mode=0644)

        rc, report = testlib.cmd(['apparmor_parser', '-a', self.pam_apparmor_policy])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def tearDown(self):
        '''Clean up after each test_* function'''

        self.default_user = None
        self.confined_user = None
        self.confined_group = None
        self.unconfined_user = None
        self.unconfined_group = None
        self.adm_group = None

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        testlib.config_restore(self.pam_su)

        if os.path.exists(self.pam_apparmor_policy):
            testlib.cmd(['apparmor_parser', '-R', self.pam_apparmor_policy])
            os.unlink(self.pam_apparmor_policy)

    def test_pam_user_group_default(self):
        '''Test pam (order=user,group,default)'''
        if self.lsb_release['Release'] <= 9.10:
            return self._skipped("TODO: verify AppArmor <= 2.3")

        order = 'user,group,default'
        allowed_access = { 'default_user' : (self.default_user_fn, self.default_user.login),
                           'confined_user' : (self.confined_user_fn, self.confined_user.login),
                           'confined_group' : (self.confined_group_fn, self.confined_group.login),
                           'unconfined_user': (self.unconfined_user_fn, self.unconfined_user.login),
                           'unconfined_group' : (self.unconfined_group_fn, self.unconfined_group.login),
                           'adm_group' : (self.confined_user_fn, self.adm_group.login),
                         }

        keys = allowed_access.keys()
        keys.sort()

        contents = "session optional pam_apparmor.so order=%s debug" % order
        testlib.config_replace(self.pam_su, contents, True)

        print ""
        for r in keys:
            fn = allowed_access[r][0]
            user = allowed_access[r][1]

            print "  %s can access %s's file" % (r, os.path.basename(fn))
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), user])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

            for other_r in keys:
                if (r == 'adm_group' and other_r == 'confined_user') or other_r == r:
                    continue
                other_fn = allowed_access[other_r][0]

                expected = 1
                if r.startswith('unconfined') or r == os.path.basename(other_fn):
                    expected = 0
                    print "  %s can access %s's file" % (r, os.path.basename(other_fn))
                else:
                    print "  %s cannot access %s's file" % (r, os.path.basename(other_fn))

                rc, report = testlib.cmd(['su', '-c', 'cat %s' % (other_fn), user])
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                if r.startswith('unconfined') or r == os.path.basename(other_fn):
                    self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))
                else:
                    self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

    def test_pam_group_user_default(self):
        '''Test pam (order=group,user,default)'''
        if self.lsb_release['Release'] <= 9.10:
            return self._skipped("TODO: verify AppArmor <= 2.3")

        order = 'group,user,default'
        allowed_access = { 'default_user' : (self.default_user_fn, self.default_user.login),
                           'confined_user' : (self.confined_user_fn, self.confined_user.login),
                           'confined_group' : (self.confined_group_fn, self.confined_group.login),
                           'unconfined_user': (self.unconfined_user_fn, self.unconfined_user.login),
                           'unconfined_group' : (self.unconfined_group_fn, self.unconfined_group.login),
                           'adm_group' : (self.adm_group_fn, self.adm_group.login),
                         }

        keys = allowed_access.keys()
        keys.sort()

        contents = "session optional pam_apparmor.so order=%s debug" % order
        testlib.config_replace(self.pam_su, contents, True)

        print ""
        for r in keys:
            fn = allowed_access[r][0]
            user = allowed_access[r][1]

            print "  %s can access %s's file" % (r, os.path.basename(fn))
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), user])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

            for other_r in keys:
                if other_r == r:
                    continue
                other_fn = allowed_access[other_r][0]

                expected = 1
                if r.startswith('unconfined'):
                    expected = 0
                    print "  %s can access %s's file" % (r, os.path.basename(other_fn))
                else:
                    print "  %s cannot access %s's file" % (r, os.path.basename(other_fn))

                rc, report = testlib.cmd(['su', '-c', 'cat %s' % (other_fn), user])
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                if r.startswith('unconfined'):
                    self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))
                else:
                    self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

    def test_pam_default_user_group(self):
        '''Test pam (order=default,user,group)'''
        if self.lsb_release['Release'] < 9.04:
            return self._skipped("TODO: verify AppArmor 2.1")

        order = 'default,user,group'
        allowed_access = { 'default_user' : (self.default_user_fn, self.default_user.login),
                           'confined_user' : (self.default_user_fn, self.confined_user.login),
                           'confined_group' : (self.default_user_fn, self.confined_group.login),
                           'unconfined_user': (self.default_user_fn, self.unconfined_user.login),
                           'unconfined_group' : (self.default_user_fn, self.unconfined_group.login),
                           'adm_group' : (self.default_user_fn, self.adm_group.login),
                         }

        keys = allowed_access.keys()
        keys.sort()

        contents = "session optional pam_apparmor.so order=%s debug" % order
        testlib.config_replace(self.pam_su, contents, True)

        print ""
        for r in keys:
            fn = allowed_access[r][0]
            user = allowed_access[r][1]

            print "  %s can access %s's file" % (r, os.path.basename(fn))
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), user])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

            for other_fn in [self.adm_group_fn, self.confined_user_fn, self.confined_group_fn, self.unconfined_user_fn, self.unconfined_group_fn]:
                print "  %s cannot access %s's file" % (r, os.path.basename(other_fn))
                expected = 1
                rc, report = testlib.cmd(['su', '-c', 'cat %s' % (other_fn), user])
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

    def test_pam_user_default_group(self):
        '''Test pam (order=user,default,group)'''
        if self.lsb_release['Release'] <= 9.10:
            return self._skipped("TODO: verify AppArmor <= 2.3")

        order = 'user,default,group'
        contents = "session optional pam_apparmor.so order=%s debug" % order
        testlib.config_replace(self.pam_su, contents, True)

        print ""

        print "  adm_group cannot access adm_group's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.adm_group_fn), self.adm_group.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        print "  adm_group can access confined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.confined_user_fn), self.adm_group.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        print "  adm_group cannot access default_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.default_user_fn), self.adm_group.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        print "  confined_user can access confined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.confined_user_fn), self.confined_user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        print "  confined_user cannot access unconfined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.unconfined_user_fn), self.confined_user.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        print "  default_user can access default_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.default_user_fn), self.default_user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        print "  default_user cannot access unconfined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.unconfined_user_fn), self.default_user.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        for fn in [self.adm_group_fn, self.confined_user_fn, self.confined_group_fn, self.default_user_fn, self.unconfined_user_fn, self.unconfined_group_fn]:
            print "  unconfined_user can access %s's file" % (os.path.basename(fn))
            expected = 0
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), self.unconfined_user.login])
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        for fn in [self.adm_group_fn, self.confined_user_fn, self.confined_group_fn, self.default_user_fn, self.unconfined_user_fn, self.unconfined_group_fn]:
            print "  unconfined_group can access %s's file" % (os.path.basename(fn))
            expected = 0
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), self.unconfined_group.login])
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

    def test_pam_group_default_user(self):
        '''Test pam (order=group,default,user)'''
        if self.lsb_release['Release'] <= 9.10:
            return self._skipped("TODO: verify AppArmor <= 2.3")

        order = 'group,default,user'
        contents = "session optional pam_apparmor.so order=%s debug" % order
        testlib.config_replace(self.pam_su, contents, True)

        print ""

        print "  adm_group can access adm_group's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.adm_group_fn), self.adm_group.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        print "  adm_group cannot access confined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.confined_user_fn), self.adm_group.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        print "  adm_group cannot access default_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.default_user_fn), self.adm_group.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        print "  confined_user can access confined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.confined_user_fn), self.confined_user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        print "  confined_user cannot access unconfined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.unconfined_user_fn), self.confined_user.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        print "  default_user can access default_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.default_user_fn), self.default_user.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        print "  default_user cannot access unconfined_user's file"
        rc, report = testlib.cmd(['su', '-c', 'cat %s' % (self.unconfined_user_fn), self.default_user.login])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFalse(self.check_string in report, "Found '%s' in report:\n%s" % (self.check_string, report))

        for fn in [self.adm_group_fn, self.confined_user_fn, self.confined_group_fn, self.default_user_fn, self.unconfined_user_fn, self.unconfined_group_fn]:
            print "  unconfined_user can access %s's file" % (os.path.basename(fn))
            expected = 0
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), self.unconfined_user.login])
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

        for fn in [self.adm_group_fn, self.confined_user_fn, self.confined_group_fn, self.default_user_fn, self.unconfined_user_fn, self.unconfined_group_fn]:
            print "  unconfined_group can access %s's file" % (os.path.basename(fn))
            expected = 0
            rc, report = testlib.cmd(['su', '-c', 'cat %s' % (fn), self.unconfined_group.login])
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(self.check_string in report, "Could not find '%s' in report:\n%s" % (self.check_string, report))

class ApparmorBindings(testlib.TestlibCase):
    '''Test bindings'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.script = os.path.join(self.tmpdir, "test-script")
        self.messages_auditd = os.path.join(self.tmpdir, "test-messages-auditd")
        self.messages_kernlog = os.path.join(self.tmpdir, "test-messages-kernlog")

        contents = '''type=APPARMOR_ALLOWED msg=audit(1257283891.471:2232): operation="file_perm" pid=4064 parent=4002 profile="/usr/bin/gedit" requested_mask="w::" denied_mask="w::" fsuid=1000 ouid=1000 name="/home/testuser/.gnome2/accels/gedit"
type=APPARMOR_DENIED msg=audit(1257283892.123:2234): operation="file_perm" pid=4064 parent=4002 profile="/usr/bin/gedit" requested_mask="w::" denied_mask="w::" fsuid=1000 ouid=1000 name="/home/testuser/.ssh/id_rsa"'''
        testlib.create_fill(self.messages_auditd, contents, mode=0644)

        contents = '''Jun 22 13:53:48 localhost kernel: [153157.745909] type=1400 audit(1308767024.828:3705): apparmor="ALLOWED" operation="open" parent=24000 profile="/usr/lib/firefox-5.0/firefox{,*[^s][^h]}" name="/home/testuser/foo" pid=24791 comm="plugin-containe" requested_mask="r" denied_mask="r" fsuid=1000 ouid=1000
Jun 22 13:53:48 localhost kernel: [153157.745909] type=1400 audit(1308767024.828:3705): apparmor="DENIED" operation="open" parent=24000 profile="/usr/lib/firefox-5.0/firefox{,*[^s][^h]}" name="/home/testuser/.ssh/id_rsa" pid=24791 comm="plugin-containe" requested_mask="r" denied_mask="r" fsuid=1000 ouid=1000'''
        testlib.create_fill(self.messages_kernlog, contents, mode=0644)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_perl(self):
        '''Test perl binding'''
        shutil.copy("./apparmor/bindings.pl", self.script)

        # auditd
        expected = 0
        rc, report = testlib.cmd([self.script, self.messages_auditd])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue("pass" in report, "Could not find 'pass' in report:\n%s" % (report))

        # kern.log
        expected = 0
        rc, report = testlib.cmd([self.script, self.messages_kernlog])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue("pass" in report, "Could not find 'pass' in report:\n%s" % (report))

    def test_python(self):
        '''Test python binding'''
        if self.lsb_release['Release'] < 11.04:
            return self._skipped("python-libapparmor not available in 10.10 and earlier")

        shutil.copy("./apparmor/bindings.py", self.script)

        pythons = ['python']
        if self.lsb_release['Release'] >= 12.10:
            pythons.append('python3')

        print ""
        for python in pythons:
            print "  %s" % python
            # auditd
            expected = 0
            rc, report = testlib.cmd([python, self.script, self.messages_auditd])
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue("pass" in report, "Could not find 'pass' in report:\n%s" % (report))

            # kern.log
            expected = 0
            rc, report = testlib.cmd([self.script, self.messages_kernlog])
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue("pass" in report, "Could not find 'pass' in report:\n%s" % (report))


class ApparmorNetwork(testlib.TestlibCase):
    '''Test network'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.exe = os.path.join(self.tmpdir, "test-net.py")

        shutil.copy("./apparmor/test-net.py", self.exe)

        self.profile = os.path.join(self.tmpdir, "test-net.profile")
        self.template = '''#include <tunables/global>
%s {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/user-tmp>

  # Allow everything besides networking, essentially
  capability dac_override, # for running under sudo
  / r,
  /** rw,
  /bin/* ix,
  /usr/bin/* ix,

@@@RULES@@@
}
''' % (self.exe)

        self.modules = []

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib.cmd(['apparmor_parser', '-R', self.profile])

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        if len(self.modules) != 0:
            for m in self.modules:
                testlib.cmd(['rmmod', m])

    def _update_profile(self, rules):
        '''Update profile with rules'''
        if os.path.exists(self.profile):
            os.unlink(self.profile)
        contents = re.sub("@@@RULES@@@", rules, self.template)
        testlib.create_fill(self.profile, contents, mode=0644)

        rc, report = testlib.cmd(['apparmor_parser', '-a', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        #print self.tmpdir
        #subprocess.call(['bash'])

    def _module_is_available(self, module):
        '''Check if a module is available as either a module or built-in'''
        if module not in self.modules:
            not_found = 'Module %s not found.' % module
            # modprobe will return 0 if kernel module is built-in
            rc, report = testlib.cmd(['modprobe', '--dry-run', module])
            if rc != 0 and not_found in report:
                return False
            # ignore all other modprobe --dry-run errors, as they'll be caught
            # in _load_module()
        return True

    def _load_module(self, module):
        '''Load module into the kernel'''
        if module not in self.modules:
            self.modules.append(module)
            rc, report = testlib.cmd(['modprobe', module])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, module)
            self.assertEquals(expected, rc, result + report)

    def test_protocol(self):
        '''Test network protocol'''
        print ""
        for p in [ 'icmp', 'tcp', 'udp' ]:
            print "  proto:%s" % p
            testlib.cmd(['apparmor_parser', '-R', self.profile])

            # no profile
            rc, report = testlib.cmd([self.exe, '-p', p])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, p)
            self.assertEquals(expected, rc, result + report)

            rules = "  network %s," % p
            if p == 'icmp':
                rules += "\n  capability net_raw,"
            self._update_profile(rules)

            # with profile
            rc, report = testlib.cmd([self.exe, '-p', p])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, p)
            self.assertEquals(expected, rc, result + report)

    def test_type(self):
        '''Test network type'''
        print ""
        # 'type', 'module'
        types = [ ('dgram', ''),
                  ('stream', ''),
                  ('raw', ''),
                  ('packet', ''),
                ]
        if self.lsb_release['Release'] > 10.04:
            types.append(('seqpacket', 'tipc'))
            types.append(('rdm', 'tipc'))
        for (t, m) in types:
            progress="  type:%s" % t
            if m != '' and not self._module_is_available(m):
                    print progress + " (skipped: Kernel module %s is not available)" % m
                    continue;
            print progress
            if m != '':
                self._load_module(m)

            rules = "  network %s," % t
            if t == 'raw' or t == 'packet':
                rules += "\n  capability net_raw,"
            elif t == 'rdm':
                rules += "\n  network tipc,"
            self._update_profile(rules)

            # with profile
            rc, report = testlib.cmd([self.exe, '-t', t])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, t)
            self.assertEquals(expected, rc, result + report)

            # no profile
            testlib.cmd(['apparmor_parser', '-R', self.profile])
            rc, report = testlib.cmd([self.exe, '-t', t])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, t)
            self.assertEquals(expected, rc, result + report)

    def test_domain(self):
        '''Test network domain'''
        # 'domain', 'module'
        domains = [ ('inet', '' ),
                    ('inet6', '' ),
                    ('ax25', 'ax25'),
                    ('x25', 'x25'),
                    ('ipx', 'ipx'),
                    ('appletalk', 'appletalk'),
                    ('netrom', 'netrom'),
                    #('bridge', 'bridge'),
                    ('atmpvc', 'atm'),
                    ('atmsvc', 'atm'),
                    ('rose', 'rose'),
                    #('netbeui', 'netbeui'),
                    ('packet', 'af_packet'),
                    #('ash', ''),
                    #('econet', 'econet'), # 12.04 and earlier
                    #('sna', ''),
                    ('irda', 'irda'),
                    ('pppox', 'pppoe'),
                    #('wanpipe', 'x25'),
                    ('bluetooth', 'bluetooth'),
                  ]
        # econet module disabled in quantal kernels
        if not self.kernel_at_least("3.5"):
            domains.append(('econet', 'econet'))
        print ""

        for (d, m) in domains:
            progress="  domain:%s" % d
            if m != '' and not self._module_is_available(m):
                print progress + " (skipped: Kernel module %s is not available)" % m
                continue
            print progress
            if m != '':
                self._load_module(m)

            rules = "  network %s," % d
            if d.startswith('inet') or d == 'packet':
                rules += "\n  capability net_raw,"
            self._update_profile(rules)

            # with profile
            rc, report = testlib.cmd([self.exe, '-d', d])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, d)
            self.assertEquals(expected, rc, result + report)

            # no profile
            testlib.cmd(['apparmor_parser', '-R', self.profile])
            rc, report = testlib.cmd([self.exe, '-d', d])
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, d)
            self.assertEquals(expected, rc, result + report)

class ApparmorEnvFilter(testlib.TestlibCase):
    '''Test network'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0755)
        self.profile = None
        self.cwd = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.profile != None:
            testlib.cmd(['apparmor_parser', '-R', self.profile])

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        self.user = None
        os.chdir(self.cwd)

    def _compile(self, path, source, target, args):
        '''Compile things'''
        # compile our test code
        if not source.startswith("/"):
            source = os.path.join(path, source)
        if not target.startswith("/"):
            target = os.path.join(path, target)
        rc, report = testlib.cmd(['gcc', source, '-o', target] + args.split())
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _run_env_test_with_helper(self, path, exe, child_exe, env_var, include_files, env_path=None, add_abstractions=[], compile_params=[], ignore_exit=False):
        '''Attempt to abstract this stuff out since we run the some 5 tests:
           - unconfined with no modified env_var
           - unconfined with evil/ in env_var
           - confined with no modified env_var
           - confined with modified env_var
           - confined with modified env_var but with symlink bypass

           Makes the following assumptions:
           - <path>/<exe> exists
           - <path>/<child_exe> exists
           - <path>evil/Templib/<included files> exists
        '''
        # prepare our temp area
        d = os.path.join(self.tmpdir, os.path.basename(path))
        shutil.copytree(path, d)
        os.chdir(d)

        for c in compile_params:
            self._compile(d, **c)

        # adjust environment strings
        clean_env_path = ""
        evil_env_path = ""
        if env_var == "GTK_MODULES": # GTK_MODULES needs an absolute path
            evil_env_path = '%s=' % env_var
            for i in include_files:
                evil_env_path = '%s=%s' % (env_var, os.path.join(d, i))
        elif env_path == None:
            evil_env_path = '%s=./evil' % env_var
        else:
            clean_env_path = "%s=%s" % (env_var, env_path)
            evil_env_path = '%s=./evil:%s' % (env_var, env_path)

        # Make sure the executable paths are ok
        if not exe.startswith('/'):
            exe = os.path.join(d, exe)
        if not child_exe.startswith('/'):
            child_exe = os.path.join(d, child_exe)

        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        testlib.cmd(['chown', '-R', '%s:%s' % (self.user.uid, self.user.gid), os.path.join(d, "evil")])

        # Make sure the script works ok unconfined
        if clean_env_path == "":
            rc, report = testlib.cmd(['sudo', '-u', self.user.login, exe])
        else:
            rc, report = testlib.cmd(['sudo', '-u', self.user.login, clean_env_path, exe])
        if not ignore_exit:
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, d)
            self.assertEquals(expected, rc, result + report)
            # the gtk test needs this here because it can't open DISPLAY
            self.assertTrue("Ok" in report, "Could not find 'Ok' in report:\n%s" % (report))

        # Make sure evil works ok
        rc, report = testlib.cmd(['sudo', '-u', self.user.login, evil_env_path, exe])
        if not ignore_exit:
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, d)
            self.assertEquals(expected, rc, result + report)

        self.assertTrue("gotcha" in report, "Could not find 'gotcha' in report:\n%s" % (report))

        # add profile
        template = '''
# Last Modified: Mon Jan  9 15:54:17 2012
#include <tunables/global>

%s {
  #include <abstractions/base>
  #include <abstractions/nameservice> # for getpwuid_r() in glib
  /bin/dash ixr, # for 'system' in interpreters
  deny @{HOME}/.Xauthority r,
  /etc/default/apport r,
  /etc/apt/apt.conf.d/ r,
  /etc/apt/apt.conf.d/** r,
  /usr/** r,
''' % (exe)
        for a in add_abstractions:
            template += "  #include <abstractions/%s>\n" % a
            # attempt to deal with interpreters
            template += "  /usr/bin/%s* ix,\n" % a
            # workaround python abstraction bug:
            if a == 'python':
                template += '''
  /usr/include/python*/pyconfig.h r,
  deny /usr/local/lib/python*/dist-packages/ r,
  /usr/share/pyshared/* r,
  deny %s/**/*.pyc w,
  # python3 started wanting to read directories in raring
  %s/ r,
  %s/**/ r,
''' % (d, d, d)

        for i in include_files:
            template += "  %s/Testlib/%s r,\n" % (d, i)

        template += '''
  %s r, #

  #include <abstractions/ubuntu-helpers>
###TEMPLATE###
}
''' % (exe)

        contents = re.sub(r'###TEMPLATE###', "  %s Ux," % child_exe, template)
        self.profile = os.path.join(self.tmpdir, "profile")
        testlib.create_fill(self.profile, contents)

        rc, report = testlib.cmd(['apparmor_parser', '-a', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Make sure the script works ok confined
        if clean_env_path == "":
            rc, report = testlib.cmd(['sudo', '-u', self.user.login, exe])
        else:
            rc, report = testlib.cmd(['sudo', '-u', self.user.login, clean_env_path, exe])
        if not ignore_exit:
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, d)
            self.assertEquals(expected, rc, result + report)
            # the gtk test needs this here because it can't open DISPLAY
            self.assertTrue("Ok" in report, "Could not find 'Ok' in report:\n%s" % (report))
        self.assertFalse("gotcha" in report, "Found 'gotcha' in report:\n%s" % (report))

        # Make sure evil does not work
        os.unlink(self.profile)
        contents = re.sub(r'###TEMPLATE###', "  %s Cx -> sanitized_helper," % child_exe, template)
        self.profile = os.path.join(self.tmpdir, "profile")
        testlib.create_fill(self.profile, contents)

        rc, report = testlib.cmd(['apparmor_parser', '-r', self.profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['sudo', '-u', self.user.login, evil_env_path, exe])
        self.assertFalse("gotcha" in report, "Found 'gotcha' in report:\n%s" % (report))

        # verify symlink bypass
        for i in os.listdir(os.path.join(d, "evil/Testlib")):
            old = os.path.join(d, "evil/Testlib", i)
            new = "%s.bypass" % old
            shutil.move(old, new)
            os.symlink(new, old)
        testlib.cmd(['chown', '-R', '%s:%s' % (self.user.uid, self.user.gid), os.path.join(d, "evil")])

        rc, report = testlib.cmd(['sudo', '-u', self.user.login, evil_env_path, exe])
        self.assertFalse("gotcha" in report, "Found 'gotcha' in report:\n%s" % (report))

    def test_envfilter_perl(self):
        '''Test perl environment filtering (PERL5LIB)'''
        if self.lsb_release['Release'] <= 13.10:
            return self._skipped("Symlinks to .pm not mediated in 13.04 and lower")
        self._run_env_test_with_helper("./apparmor/envfiltering/perl", "exe_perl", "child.pl", "PERL5LIB", ['Stuff.pm'], add_abstractions=['perl'])

    def test_envfilter_python(self):
        '''Test python environment filtering (PYTHONPATH)'''
        self._run_env_test_with_helper("./apparmor/envfiltering/python", "bin/exe_python", "bin/child.py", "PYTHONPATH", ['__init__.py', 'Stuff.py'], env_path="./", add_abstractions=['python'])

    def test_envfilter_python3(self):
        '''Test python3 environment filtering (PYTHONPATH)'''
        if self.lsb_release['Release'] < 12.10:
            return self._skipped("'python3-libapparmor' not in 12.04 and earlier")
        self._run_env_test_with_helper("./apparmor/envfiltering/python", "bin/exe_python3", "bin/child3.py", "PYTHONPATH", ['__init__.py', 'Stuff.py'], env_path="./", add_abstractions=['python'])

    def test_envfilter_compiled(self):
        '''Test compiled libraries environment filtering (mmap)'''
        # Build up arguments for compiling our code
        compile_params = []

        params = dict(source="./evil/Testlib/evil.c",
                      target="./evil/Testlib/evil.so",
                      args="-shared -fPIC")
        compile_params.append(params)

        rc, pkg_config = testlib.cmd(['pkg-config', '--cflags', '--libs', 'gtk+-2.0'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + pkg_config)
        params = dict(source="./exe.c",
                      target="./exe",
                      args=pkg_config)
        compile_params.append(params)

        params = dict(source="./child_exe.c",
                      target="./child_exe",
                      args=pkg_config)
        compile_params.append(params)

        self._run_env_test_with_helper("./apparmor/envfiltering/compiled", "exe", "child_exe", "GTK_MODULES", ['evil/Testlib/evil.so'], compile_params=compile_params, ignore_exit=True)

class ApparmorUnixDomainConnect(testlib.TestlibCase):
    '''Test mediation of file based UNIX domain sockets connect()'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0755)

        self.profile = None

        self.sock_path = os.path.join(self.tmpdir, 'sock')
        self.sock = 0

        self.exe = os.path.join(self.tmpdir, "test-unix-domain-connect.py")
        shutil.copy("./apparmor/test-unix-domain-connect.py", self.exe)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.sock:
            self.sock.close()

        if self.profile != None:
            testlib.cmd(['apparmor_parser', '-R', self.profile])

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _setup_socket(self, sock_type):
        self.sock = socket.socket(socket.AF_UNIX, sock_type)
        self.sock.settimeout(5)
        self.sock.bind(self.sock_path)
        if sock_type != socket.SOCK_DGRAM:
            self.sock.listen(3)

    def _load_profile(self, socket_access):
        socket_rule_modifier = ''
        if not socket_access:
            socket_rule_modifier = 'audit deny '

        contents = '''
#include <tunables/global>
%s {
  #include <abstractions/base>
  #include <abstractions/python>

  %s r,

  %s%s rw,
}
''' % (self.exe, self.exe, socket_rule_modifier, self.sock_path)

        profile = os.path.join(self.tmpdir, 'profile')
        testlib.create_fill(profile, contents, mode=0644)

        rc, report = testlib.cmd(['apparmor_parser', '-r', profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.profile = profile

    def _test_sock_type(self, sock_type):
        sock_types = dict(stream=socket.SOCK_STREAM, dgram=socket.SOCK_DGRAM, seqpacket=socket.SOCK_SEQPACKET)

        self._setup_socket(sock_types[sock_type])

        # Unconfined test
        rc, report = testlib.cmd([self.exe, '-p', self.sock_path, '-t', sock_type])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Confined and allowed test
        self._load_profile(True)
        rc, report = testlib.cmd([self.exe, '-p', self.sock_path, '-t', sock_type])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Confined and not allowed test
        self._load_profile(False)
        rc, report = testlib.cmd([self.exe, '-p', self.sock_path, '-t', sock_type])
        if self.lsb_release['Release'] >= 13.10:
            expected = 1
        else:
            expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_sock_dgram(self):
        '''Test mediation of file based SOCK_DGRAM connect'''
        self._test_sock_type('dgram')

    def test_sock_seqpacket(self):
        '''Test mediation of file based SOCK_SEQPACKET connect'''
        self._test_sock_type('seqpacket')

    def test_sock_stream(self):
        '''Test mediation of file based SOCK_STREAM connect'''
        self._test_sock_type('stream')

if __name__ == '__main__':
    testlib.require_sudo()

    if (len(sys.argv) > 1 and sys.argv[1] != '-v'):
        if "--with-subdomain-stress" in sys.argv:
            run_subdomain_stress = True
        if "--with-parser-stress" in sys.argv:
            run_parser_stress = True

    printk_ratelimit = file("/proc/sys/kernel/printk_ratelimit").read().splitlines()[0]
    if printk_ratelimit != "0":
        print "\nWARN: kernel rate limiting in effect"
        print "Disabling ratelimiting until the next reboot. To renable, run:"
        print "# sysctl -w kernel.printk_ratelimit=%s\n" % printk_ratelimit
        testlib.cmd(['sysctl', '-w', "kernel.printk_ratelimit=0"])

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorBindings))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorNetwork))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorApport))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorPAM))
    if os.path.exists("/etc/apparmor.d/abstractions/ubuntu-helpers"):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorEnvFilter))
    else:
        print >>sys.stderr, "Skipping AppArmorEnvFilter (no ubuntu-helpers)"
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorUnixDomainConnect))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ApparmorTestsuites))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

