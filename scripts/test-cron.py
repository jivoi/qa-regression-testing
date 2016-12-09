#!/usr/bin/python
#
#    test-cron.py quality assurance test script for cron
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Jamie Strandboge
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
# QRT-Packages: cron build-essential sudo
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
## QRT-Depends: cron
# privileges needed
# QRT-Privilege: root

'''
    *** WARNING ***
    DO NOT RUN ON A PRODUCTION MACHINE. YOU HAVE BEEN WARNED.

    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install cron build-essential sudo && ./test-cron.py -v'
'''


import unittest, subprocess, sys
import testlib
import os
import tempfile
import time

try:
    from private.qrt.Pkg import PrivatePkgTest
except ImportError:
    class PrivatePkgCron(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PkgCron(testlib.TestlibCase, PrivatePkgCron):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.daemon = testlib.TestDaemon("/etc/init.d/cron")
        self.daemon.restart()

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        self.seconds = 130

        self.spooldir = "/var/spool/cron/crontabs"
        self.script = os.path.join(self.tmpdir, "test.sh")
        self.cronfile = os.path.join(self.tmpdir, "test.cron")
        self.works = os.path.join(self.tmpdir, "it_works")

        contents = '''#!/bin/sh
set -e
touch %s
''' % (self.works)
        testlib.create_fill(self.script, contents, mode=0755)

        contents = "*/1 * * * *	%s\n" % (self.script)
        testlib.create_fill(self.cronfile, contents)

        self.user = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        os.chown(os.path.dirname(self.works), self.user.uid, self.user.gid)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(os.path.join(self.spooldir, self.user.login)):
            os.unlink(os.path.join(self.spooldir, self.user.login))
        self.user = None

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        # dirty, but shouldn't be running on producti0n anyway...
        if os.path.exists("/etc/cron.allow"):
            os.unlink("/etc/cron.allow")

        if os.path.exists("/etc/cron.deny"):
            os.unlink("/etc/cron.deny")

    def test_init(self):
        '''Test initscript'''
        res, output = self.daemon.stop()
        self.assertTrue(res, output)

        res, output = self.daemon.start()
        self.assertTrue(res, output)

        res, output = self.daemon.restart()
        self.assertTrue(res, output)

        res, output = self.daemon.reload()
        self.assertTrue(res, output)

        if self.lsb_release['Release'] <= 8.04:
            self._skipped("'status' (unsupported on %s)" % (str(self.lsb_release['Release'])))
        else:
            res, output = self.daemon.status()
            self.assertTrue(res, output)

    def test_cron_allow(self):
        '''Test /etc/cron.allow'''
        testlib.create_fill("/etc/cron.allow", self.user.login + "\n")
        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'crontab', self.cronfile])
        expected = 0
        result = "Got exit code %d\n" % (rc)
        self.assertTrue(rc == expected, result + report)

        subprocess.call(['sed', '-i', 's#%s##g' % (self.user.login), "/etc/cron.allow"])
        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'crontab', self.cronfile])
        expected = 1
        result = "Got exit code %d\n" % (rc)
        self.assertTrue(rc == expected, result + report)

    def test_cron_deny(self):
        '''Test /etc/cron.deny'''
        testlib.create_fill("/etc/cron.deny", self.user.login + "\n")
        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'crontab', self.cronfile])
        expected = 1
        result = "Got exit code %d\n" % (rc)
        self.assertTrue(rc == expected, result + report)

        subprocess.call(['sed', '-i', 's#%s##g' % (self.user.login), "/etc/cron.deny"])
        rc, report = testlib.cmd(['sudo', '-u', self.user.login, 'crontab', self.cronfile])
        expected = 0
        result = "Got exit code %d\n" % (rc)
        self.assertTrue(rc == expected, result + report)

    def test_crontab(self):
        '''Test crontab'''
        # we always operate on self.user's crontab, but first as root using
        # 'crontab -u' and then as the user without '-u'
        for use_sudo in ['False', 'True']:
            cmd = ['crontab', '-u', self.user.login]
            if use_sudo:
                cmd = ['sudo', '-u', self.user.login, 'crontab']

            # should have an empty crontab
            rc, report = testlib.cmd(cmd + ['-l'])
            expected = 1
            result = "Got exit code %d using '%s'\n" % (rc, cmd)
            self.assertTrue(rc == expected, result + report)

            # add crontab
            rc, report = testlib.cmd(cmd + [self.cronfile])
            expected = 0
            result = "Got exit code %d using '%s'\n" % (rc, cmd)
            self.assertTrue(rc == expected, result + report)

            # should have a crontab
            rc, report = testlib.cmd(cmd + ['-l'])
            expected = 0
            result = "Got exit code %d using '%s'\n" % (rc, cmd)
            self.assertTrue(rc == expected, result + report)

            # remove crontab
            rc, report = testlib.cmd(cmd + ['-r'])
            expected = 0
            result = "Got exit code %d using '%s'\n" % (rc, cmd)
            self.assertTrue(rc == expected, result + report)

            # should have an empty crontab
            rc, report = testlib.cmd(cmd + ['-l'])
            expected = 1
            result = "Got exit code %d using '%s'\n" % (rc, cmd)
            self.assertTrue(rc == expected, result + report)

    def test_bad_crontab(self):
        '''Test bad crontab'''
        subprocess.call(['sed', '-i', 's#*/1##g', self.cronfile])

        for use_sudo in ['False', 'True']:
            cmd = ['crontab', '-u', self.user.login]
            if use_sudo:
                cmd = ['sudo', '-u', self.user.login, 'crontab']

            # add crontab
            rc, report = testlib.cmd(cmd + [self.cronfile])
            expected = 1
            result = "Got exit code %d using '%s'\n" % (rc, cmd)
            self.assertTrue(rc == expected, result + report)

    def test_scheduler(self):
        '''Test scheduler'''
        rc, report = testlib.cmd(['crontab', '-u', self.user.login, self.cronfile])
        expected = 0
        result = "Got exit code %d\n" % (rc)
        self.assertTrue(rc == expected, result + report)

        print ""
        print "  Waiting '%d' seconds..." % (self.seconds)
        time.sleep(self.seconds)
        self.assertTrue(os.path.exists(self.works), "'%s' does not exist" % (self.works))

    def test_drop_privs(self):
        '''Test dropped privileges'''
        contents = '''#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[])
{
        printf("uid=%d\\neuid=%d\\n", getuid(), geteuid());
        printf("gid=%d\\negid=%d\\n", getgid(), getegid());
        return 0;
}
'''
        source = os.path.join(self.tmpdir, "46649.c")
        binary = os.path.join(self.tmpdir, "46649")
        testlib.create_fill(source, contents)
        rc, report = testlib.cmd(['gcc', '-o', binary, source])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.unlink(self.script)
        contents = '''#!/bin/sh
set -e
%s
''' % (binary)
        testlib.create_fill(self.script, contents, mode=0755)

        os.unlink(self.cronfile)
        contents = "*/1 * * * *	%s > %s\n" % (self.script, self.works)
        testlib.create_fill(self.cronfile, contents)

        rc, report = testlib.cmd(['crontab', '-u', self.user.login, self.cronfile])
        expected = 0
        result = "Got exit code %d\n" % (rc)
        self.assertTrue(rc == expected, result + report)

        print ""
        print "  Waiting '%d' seconds..." % (self.seconds)
        time.sleep(self.seconds)
        self.assertTrue(os.path.exists(self.works), "'%s' does not exist" % (self.works))

        try:
            fh = open(self.works, 'r')
        except:
            raise
        lines = []
        for line in fh.readlines():
            lines.append(line.rstrip())
        fh.close()

        search_str = "uid=%s" % (self.user.uid)
        self.assertTrue(search_str in lines, "Could not find '%s' in:%s" % (search_str, lines))

        search_str = "euid=%s" % (self.user.uid)
        self.assertTrue(search_str in lines, "Could not find '%s' in:%s" % (search_str, lines))

        search_str = "gid=%s" % (self.user.gid)
        self.assertTrue(search_str in lines, "Could not find '%s' in:%s" % (search_str, lines))

        search_str = "egid=%s" % (self.user.gid)
        self.assertTrue(search_str in lines, "Could not find '%s' in:%s" % (search_str, lines))

if __name__ == '__main__':
    # simple
    unittest.main()
