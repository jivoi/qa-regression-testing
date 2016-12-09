#!/usr/bin/python
#
#    test-sudo.py quality assurance test script for sudo
#    Copyright (C) 2009-2015 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#            Jamie Strandboge <jamie@canonical.com>
#            Marc Deslauriers <marc.deslauriers@canonical.com>
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

'''
    TODO:

      get test_timestamps() to work-- the combination of sudo ./test-sudo.py,
        su -c and sudo -[kKv] gets a little complicated and so this test is
        disabled for now
'''
# QRT-Packages: python-pexpect sudo dash build-essential
# QRT-Privilege: root

import unittest, sys, os, re
import grp
import pexpect
import shutil
import testlib
import tempfile
import time

# shared among different tests
outsider = None
escaper = None
confined = None
geese = None

def sudo_group(release):
    if release < 12.04:
        return 'admin'

    for gr in grp.getgrall():
        if gr.gr_name == 'admin':
            # upgraded systems may still use the admin group
            return 'admin'

    return 'sudo'

class SudoTest(testlib.TestlibCase):
    '''Test sudo silliness.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.ro_file = "/etc/hosts"
        self.ro_file_snippet = "localhost"
        self.tmpdir = ""
        self.rundir = "/var/run/sudo"
        if self.lsb_release['Release'] >= 10.10:
            self.rundir = "/var/lib/sudo"
        self.assertTrue(os.path.exists(self.rundir))
        self.sudo_group = sudo_group(self.lsb_release['Release'])
        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        # Do NOT restore the sudoers file here due to shared configurations
        # among different sets of tests.
        os.chdir(self.current_dir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _sudo_touser_fromuser(self, touser, fromuser, desired):
        rc = True
        child = pexpect.spawn('su -c "sudo -u %s id" %s' % (touser, fromuser), timeout=2)
        if child.expect([r'uid=[0-9]+\(%s\) '%(touser),r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) != 0:
            rc = False
        child.kill(0)
        self.assertTrue(rc == desired, str(child.before) + str(child.after))

    def _sudo_togroup_fromuser(self, togroup, fromuser, desired):
        rc = True
        child = pexpect.spawn('su -c "sudo -g %s id" %s' % (togroup, fromuser), timeout=2)
        if child.expect([r'gid=[0-9]+\(%s\) '%(togroup),r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) != 0:
            rc = False
        child.kill(0)
        self.assertTrue(rc == desired, str(child.before) + str(child.after))

    def _sudo_touserandgroup_fromuser(self, touser, togroup, fromuser, desired):
        rc = True
        child = pexpect.spawn('su -c "sudo -u %s -g %s id" %s' % (touser, togroup, fromuser), timeout=2)
        if child.expect([r'uid=[0-9]+\(%s\) '%(touser),r'gid=[0-9]+\(%s\) '%(togroup),r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) != 0:
            rc = False
        child.kill(0)
        self.assertTrue(rc == desired, str(child.before) + str(child.after))


    def test_runas_aa_setup(self):
        '''Setup runas tests'''
        # confined can become outsider or escaper
        # confined can NOT become root
        # escaper can become outsider
        # escaper can NOT become root   (*)
        # outsider can NOT become anyone
        global geese
        global outsider
        global confined
        global escaper

        # geese group
        geese = testlib.TestGroup()
        # outsider not in geese
        outsider = testlib.TestUser()
        # confined not in geese
        confined = testlib.TestUser()
        # escaper in geese
        escaper = testlib.TestUser()
        escaper.add_to_group(geese.group)

        # CVE-2009-0034
        testlib.config_replace('/etc/sudoers','''
Runas_Alias RUNASLIST = %s,%%%s
%s ALL=(RUNASLIST) NOPASSWD: ALL
%s ALL=(RUNASLIST) NOPASSWD: ALL
''' % (outsider.login, geese.group, escaper.login, confined.login),append=True)
        os.chmod('/etc/sudoers',0440)

    def test_runas_bb_confined(self):
        '''Test 'confined' can sudo to outsider and escaper, not root'''
        self._sudo_touser_fromuser('root', confined.login, False)
        self._sudo_touser_fromuser(outsider.login, confined.login, True)
        self._sudo_touser_fromuser(escaper.login, confined.login, True)

    def test_runas_cc_da_outsider(self):
        '''Test 'outsider' can sudo to nothing'''
        self._sudo_touser_fromuser('root', outsider.login, False)
        self._sudo_touser_fromuser(escaper.login, outsider.login, False)
        self._sudo_touser_fromuser(confined.login, outsider.login, False)

    def test_runas_dd_escaper(self):
        '''Test 'escaper' can sudo to outsider, not root or confined (CVE-2009-0034)'''
        self._sudo_touser_fromuser('root', escaper.login, False)
        self._sudo_touser_fromuser(outsider.login, escaper.login, True)
        self._sudo_touser_fromuser(confined.login, escaper.login, False)

    def test_runas_ee_used_user(self):
        '''Test -g not allowed when not using :GROUP'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        self._sudo_touserandgroup_fromuser(confined.login, 'root', confined.login, False)
        self._sudo_touserandgroup_fromuser(confined.login, outsider.login, confined.login, False)
        self._sudo_touserandgroup_fromuser(confined.login, escaper.login, confined.login, False)

        self._sudo_touserandgroup_fromuser(outsider.login, 'root', outsider.login, False)
        self._sudo_touserandgroup_fromuser(outsider.login, escaper.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser(outsider.login, confined.login, outsider.login, False)

        self._sudo_touserandgroup_fromuser(escaper.login, 'root', escaper.login, False)
        self._sudo_touserandgroup_fromuser(escaper.login, outsider.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser(escaper.login, confined.login, escaper.login, False)

    def test_runas_zz_cleanup(self):
        '''Cleanup runas tests'''
        global geese
        global outsider
        global confined
        global escaper

        # remove all timestamps for our users
        for i in [confined.login, outsider.login, escaper.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        outsider = None
        escaper = None
        confined = None
        geese = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)


    def test_runasgroup_aa_setup(self):
        '''Setup runas group tests'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        # confined can become group outsider or group escaper
        # confined can become outsider and group escaper
        # confined can NOT become group root
        # escaper can become group outsider
        # escaper can NOT become group root
        # outsider can NOT become group anyone
        global geese
        global outsider
        global confined
        global escaper

        # geese group
        geese = testlib.TestGroup()
        # outsider not in geese
        outsider = testlib.TestUser()
        # confined not in geese
        confined = testlib.TestUser()
        # escaper in geese
        escaper = testlib.TestUser()
        escaper.add_to_group(geese.group)

        testlib.config_replace('/etc/sudoers','''
%s ALL=(:%s) NOPASSWD: ALL
%s ALL=(:%s) NOPASSWD: ALL
%s ALL=(:%s) NOPASSWD: ALL
%s ALL=(%s:%s) NOPASSWD: ALL
''' % (confined.login, outsider.login, \
       confined.login, escaper.login, \
       escaper.login, outsider.login, \
       confined.login, outsider.login, escaper.login), \
       append=True)
        os.chmod('/etc/sudoers',0440)

    def test_runasgroup_bb_confined(self):
        '''Test 'confined' can sudo to group outsider and escaper, not root'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        self._sudo_togroup_fromuser('root', confined.login, False)
        self._sudo_togroup_fromuser(outsider.login, confined.login, True)
        self._sudo_togroup_fromuser(escaper.login, confined.login, True)
        self._sudo_touserandgroup_fromuser(confined.login, 'root', confined.login, False)
        self._sudo_touserandgroup_fromuser(confined.login, outsider.login, confined.login, True)
        self._sudo_touserandgroup_fromuser(confined.login, escaper.login, confined.login, True)


    def test_runasgroup_cc_da_outsider(self):
        '''Test 'outsider' can sudo to nothing'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        self._sudo_togroup_fromuser('root', outsider.login, False)
        self._sudo_togroup_fromuser(escaper.login, outsider.login, False)
        self._sudo_togroup_fromuser(confined.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser(outsider.login, 'root', outsider.login, False)
        self._sudo_touserandgroup_fromuser(outsider.login, escaper.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser(outsider.login, confined.login, outsider.login, False)

    def test_runasgroup_dd_escaper(self):
        '''Test 'escaper' can sudo to group outsider, not root or confined'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        self._sudo_togroup_fromuser('root', escaper.login, False)
        self._sudo_togroup_fromuser(outsider.login, escaper.login, True)
        self._sudo_togroup_fromuser(confined.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser(escaper.login, 'root', escaper.login, False)
        self._sudo_touserandgroup_fromuser(escaper.login, outsider.login, escaper.login, True)
        self._sudo_touserandgroup_fromuser(escaper.login, confined.login, escaper.login, False)

    def test_runasgroup_ee_user_and_group(self):
        '''Test -u and -g combinations'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        # -u 'me' will pass if -g is allowed, so ignore that
        self._sudo_touserandgroup_fromuser(outsider.login, escaper.login, confined.login, True)
        self._sudo_touserandgroup_fromuser(escaper.login, escaper.login, confined.login, False)
        self._sudo_touserandgroup_fromuser('root', escaper.login, confined.login, False)

        # The following has changed behaviour in 1.8.2: "If the user
        # specifies a group via sudo's -g option that matches the target
        # user's group in the password database, it is now allowed even if
        # no groups are present in the Runas_Spec."

        if self.lsb_release['Release'] >= 12.04:
            expected = True
        else:
            expected = False
        self._sudo_touserandgroup_fromuser(outsider.login, outsider.login, confined.login, expected)

        self._sudo_touserandgroup_fromuser(escaper.login, outsider.login, confined.login, False)
        self._sudo_touserandgroup_fromuser('root', outsider.login, confined.login, False)

        self._sudo_touserandgroup_fromuser(confined.login, escaper.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser(escaper.login, escaper.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser('root', escaper.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser(confined.login, outsider.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser(escaper.login, outsider.login, outsider.login, False)
        self._sudo_touserandgroup_fromuser('root', outsider.login, outsider.login, False)

        self._sudo_touserandgroup_fromuser(outsider.login, escaper.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser(confined.login, escaper.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser('root', escaper.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser(outsider.login, outsider.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser(confined.login, outsider.login, escaper.login, False)
        self._sudo_touserandgroup_fromuser('root', outsider.login, escaper.login, False)

    def test_runasgroup_zz_cleanup(self):
        '''Cleanup runas group tests'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        global geese
        global outsider
        global confined
        global escaper

        # remove all timestamps for our users
        for i in [confined.login, outsider.login, escaper.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        outsider = None
        escaper = None
        confined = None
        geese = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)


    def test_sudoedit_aa_setup(self):
        '''Setup sudoedit tests'''
        # confined can sudoedit
        # outsider can NOT sudoedit
        global outsider
        global confined

        outsider = testlib.TestUser()
        confined = testlib.TestUser()

        testlib.config_replace('/etc/sudoers','''
Defaults !env_editor,editor=/bin/cat
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
%s     ALL=(ALL) NOPASSWD: sudoedit %s
''' % (self.sudo_group, confined.login, self.ro_file))
        os.chmod('/etc/sudoers', 0440)

    def test_sudoedit_bb_allowed(self):
        '''Test sudoedit for allowed file'''
        def _run_sudoedit(asuser, cmd, desired):
            rc = True
            child = pexpect.spawn('sudo -u %s %s"' % (asuser, cmd), timeout=2)

            # return False if the command didn't work (ie, list index != 0)
            if child.expect([r'%s' % self.ro_file_snippet, r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) != 0:
                rc = False
            child.kill(0)
            report = "sudo -u %s %s returned '%s'\n" % (asuser, cmd, str(rc))
            self.assertTrue(rc == desired, report + str(child.before) + str(child.after))

        for cmd in ['sudoedit', 'sudo -e']:
            _run_sudoedit(confined.login, "%s %s" % (cmd, self.ro_file), True)
            _run_sudoedit(outsider.login, "%s %s" % (cmd, self.ro_file), False)

    def test_sudoedit_cc_disallowed(self):
        '''Test sudoedit for not allowed file'''
        def _run_sudoedit(asuser, cmd, desired):
            rc = True
            child = pexpect.spawn('sudo -u %s %s /etc/passwd"' % (asuser, cmd), timeout=2)

            # return False if the command didn't work (ie, list index != 0)
            if child.expect([r'%s:' % asuser,r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) != 0:
                rc = False
            child.kill(0)
            report = "'sudo -u %s %s /etc/passwd' returned '%s'\n" % (asuser, cmd, str(rc))
            self.assertTrue(rc == desired, report + str(child.before) + str(child.after))

        for cmd in ['sudoedit', 'sudo -e']:
            _run_sudoedit(confined.login, "%s" % (cmd), False)
            _run_sudoedit(outsider.login, "%s" % (cmd), False)

    def test_sudoedit_dd_CVE_2010_0426(self):
        '''Test CVE-2010-0426'''
        def _run_bad_sudoedit(asuser, fn, desired):
            rc = True
            child = pexpect.spawn('su -c "sudo ./sudoedit %s" %s' % (fn, asuser), timeout=2)

            # return False if the command didn't work (ie, list index != 0)
            if child.expect([r'%s:' % asuser,r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) != 0:
                rc = False
            child.kill(0)
            report = "'su -c \"sudo ./sudoedit %s\" %s' returned '%s'\n" % (fn, asuser, str(rc))

            tmp = re.split('\n', str(child.before))
            if len(tmp) > 3:
                tmp_n = 3
            else:
                tmp_n = 1
            before_output = "displaying only %d line(s) of 'before' output:\n%s" % (tmp_n, "\n".join(tmp[0:tmp_n]))
            self.assertTrue(rc == desired, report + before_output + str(child.after))

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        script = os.path.join(self.tmpdir, "sudoedit")
        contents = '''#!/bin/sh -e
cat /etc/shadow
'''
        testlib.create_fill(script, contents, mode=0755)
        os.chmod(self.tmpdir, 0775)
        os.chdir(self.tmpdir)

        for fn in [self.ro_file, '/etc/passwd']:
            _run_bad_sudoedit(confined.login, fn, False)
            _run_bad_sudoedit(outsider.login, fn, False)

    def test_sudoedit_zz_cleanup(self):
        '''Cleanup sudoedit tests'''
        global outsider
        global confined

        # remove all timestamps for our users
        for i in [confined.login, outsider.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        outsider = None
        confined = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

    def test_CVE_2010_0427_aa_setup(self):
        '''Setup CVE-2010-0427 tests'''
        global confined
        confined = testlib.TestUser()

        testlib.config_replace('/etc/sudoers','''
Defaults runas_default=%s
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
''' % (confined.login, self.sudo_group))
        os.chmod('/etc/sudoers', 0440)

    def test_CVE_2010_0427_bb_preserve_groups(self):
        '''Test preserve groups (-P)'''
        child = pexpect.spawn('sudo -P id', timeout=2)
        ret = child.expect([r'uid=[0-9]+\(%s\) '%(confined.login),pexpect.EOF,pexpect.TIMEOUT])
        child.kill(0)
        self.assertTrue(ret == 0, "Couldn't find '%s' with 'sudo -P id'\n" % (confined.login) + str(child.before) + str(child.after))

        child = pexpect.spawn('sudo -P id', timeout=2)
        ret = child.expect([r'groups=(.*,|)0\(root\)', pexpect.EOF, pexpect.TIMEOUT])
        child.kill(0)
        self.assertTrue(ret == 0, "Could not find 'groups=.*0(root)' with 'sudo -P id'\n" + str(child.before) + str(child.after))

    def test_CVE_2010_0427_cc(self):
        '''Test CVE-2010-0427'''
        child = pexpect.spawn('sudo id', timeout=2)
        ret = child.expect([r'uid=[0-9]+\(%s\) '%(confined.login),pexpect.EOF,pexpect.TIMEOUT])
        child.kill(0)
        self.assertTrue(ret == 0, "Couldn't find '%s' with 'sudo id'\n" % (confined.login) + str(child.before) + str(child.after))

        child = pexpect.spawn('sudo id', timeout=2)
        ret = child.expect([r'groups=0\(root\)', pexpect.EOF, pexpect.TIMEOUT])
        child.kill(0)
        self.assertFalse(ret == 0, "Found 'groups=0(root)' with 'sudo id'\n" + str(child.before) + str(child.after))

    def test_CVE_2010_0427_zz_cleanup(self):
        '''Cleanup CVE-2010-0427 tests'''
        global confined

        # remove all timestamps for our users
        for i in [confined.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        confined = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

    def test_CVE_2010_1646_aa_setup(self):
        '''Setup CVE-2010-1646 tests'''
        global escaper
        escaper = testlib.TestUser()

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0755)

        target_dir = "/tmp/CVE-2010-1646"

        # This test requires 'dash'. bash and pdksh don't seem affected
        contents = '''#!/bin/dash\ndate\n'''
        trusted_script = os.path.join(self.tmpdir, "trusted")
        testlib.create_fill(trusted_script, contents)
        os.chmod(trusted_script, 0755)
        trusted_script = os.path.join(target_dir, "trusted")

        shutil.copy("/usr/bin/whoami", os.path.join(self.tmpdir, "date"))

        # Sudo 1.8.x packages don't have --with-secure-path set at build
        # time anymore, and need to have it specified in the sudoers file
        if self.lsb_release['Release'] >= 12.04:
            sudoers_file = '''
Defaults	!lecture,tty_tickets,!fqdn
Defaults	secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
%s ALL=(ALL) NOPASSWD: %s
''' % (self.sudo_group, escaper.login, trusted_script)
        else:
            sudoers_file = '''
Defaults	!lecture,tty_tickets,!fqdn
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
%s ALL=(ALL) NOPASSWD: %s
''' % (self.sudo_group, escaper.login, trusted_script)

        testlib.config_replace('/etc/sudoers', sudoers_file)
        os.chmod('/etc/sudoers', 0440)

        source = os.path.join(self.tmpdir, "CVE-2010-1646.c")
        binary = os.path.join(self.tmpdir, "CVE-2010-1646")
        contents = '''#include <unistd.h>
int main()
{
    execle("/usr/bin/sudo",
           "sudo",
           "%s",
           (char *)NULL,
           (char *[]){ "PATH=%s", "PATH=%s", NULL });
}
''' % (trusted_script, target_dir, target_dir)
        testlib.create_fill(source, contents)

        rc, report = testlib.cmd(['gcc', '-o', binary, source])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        shutil.move(self.tmpdir, target_dir)

    def test_CVE_2010_1646_bb_escalate(self):
        '''Test CVE-2010-1646'''
        cvedir = os.path.join("/tmp", "CVE-2010-1646")
        os.chdir(cvedir)
        trusted_script = os.path.join(cvedir, "trusted")

        # works like it is intended
        rc, report = testlib.cmd(['su', '-c', 'sudo %s' % trusted_script, escaper.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(':' in report, "Could not find ':' in: %s" % report)

        # verify we can run 'id' under su -c properly
        rc, report = testlib.cmd(['su', '-c' '/usr/bin/id', escaper.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue(escaper.login in report, "Could not find '%s' in: %s" % (escaper.login, report))

        # does not run 'whoami'
        rc, report = testlib.cmd(['su', '-c', './CVE-2010-1646', escaper.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertFalse('root' in report, "Found 'root' in: %s" % report)
        self.assertTrue(':' in report, "Could not find ':' in: %s" % report)

    def test_CVE_2010_1646_zz_cleanup(self):
        '''Cleanup CVE-2010-1646 tests'''
        global escaper

        # remove all timestamps for our users
        for i in [escaper.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        escaper = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

        cvedir = os.path.join("/tmp", "CVE-2010-1646")
        if os.path.exists(cvedir):
            testlib.recursive_rm(cvedir)

    def test_CVE_2010_2956_aa_setup(self):
        '''Setup CVE-2010-2956 tests'''
        global escaper
        global geese
        escaper = testlib.TestUser()
        geese = testlib.TestGroup()
        exe = "/bin/cat /etc/shadow"

        runas = "%s:%s" % (escaper.login, geese.group)
        if self.lsb_release['Release'] < 9.10:
            runas = "%s" % (escaper.login)

        testlib.config_replace('/etc/sudoers','''
Defaults	!lecture,tty_tickets,!fqdn
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
%s ALL=(%s) NOPASSWD: %s
''' % (self.sudo_group, escaper.login, runas, exe))
        os.chmod('/etc/sudoers', 0440)

    def test_CVE_2010_2956_bb(self):
        '''Test CVE-2010-2956'''
        os.chdir("/tmp")
        exe = "/bin/cat /etc/shadow"

        # -g not supported in sudo 1.6
        if self.lsb_release['Release'] >= 9.10:
            rc, report = testlib.cmd(['su', '-c', 'sudo -S -u %s -g %s %s' % (escaper.login, geese.group, exe), escaper.login])
            expected = 1
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            tmp = re.split('\n', report)
            if len(tmp) > 3:
                tmp_n = 3
            else:
                tmp_n = 1
            report_trunc = "displaying only %d line(s) of report output:\n%s" % (tmp_n, "\n".join(tmp[0:tmp_n]))
            self.assertEquals(expected, rc, result + report_trunc)
            self.assertTrue("Permission denied" in report, "Could not find 'Permission denied' in: %s" % report_trunc)

            rc, report = testlib.cmd(['su', '-c', 'sudo -S -g %s %s' % (geese.group, exe), escaper.login])
            expected = 1
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            tmp = re.split('\n', report)
            if len(tmp) > 3:
                tmp_n = 3
            else:
                tmp_n = 1
            report_trunc = "displaying only %d line(s) of report output:\n%s" % (tmp_n, "\n".join(tmp[0:tmp_n]))
            self.assertEquals(expected, rc, result + report_trunc)
            self.assertTrue("Permission denied" in report, "Could not find 'Permission denied' in: %s" % report_trunc)

            # The actual CVE
            got_prompt = False
            child = pexpect.spawn('su -c "sudo -S -u root -g %s %s" %s' % (geese.group, exe, escaper.login), timeout=2)
            if child.expect([r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) == 0:
                got_prompt = True
            child.kill(0)
            tmp = re.split('\n', str(child.before))
            if len(tmp) > 3:
                tmp_n = 3
            else:
                tmp_n = 1
            before_output = "displaying only %d line(s) of 'before' output:\n%s" % (tmp_n, "\n".join(tmp[0:tmp_n]))
            self.assertTrue(got_prompt, before_output + str(child.after))

        got_prompt = False
        child = pexpect.spawn('su -c "sudo -S -u root %s" %s' % (exe, escaper.login), timeout=2)
        if child.expect([r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) == 0:
            got_prompt = True
        child.kill(0)
        tmp = re.split('\n', str(child.before))
        if len(tmp) > 3:
            tmp_n = 3
        else:
            tmp_n = 1
        before_output = "displaying only %d line(s) of 'before' output:\n%s" % (tmp_n, "\n".join(tmp[0:tmp_n]))
        self.assertTrue(got_prompt, before_output + str(child.after))

        got_prompt = False
        child = pexpect.spawn('su -c "sudo -S %s" %s' % (exe, escaper.login), timeout=2)
        if child.expect([r'[pP]assword',pexpect.EOF,pexpect.TIMEOUT]) == 0:
            got_prompt = True
        child.kill(0)
        tmp = re.split('\n', str(child.before))
        if len(tmp) > 3:
            tmp_n = 3
        else:
            tmp_n = 1
        before_output = "displaying only %d line(s) of 'before' output:\n%s" % (tmp_n, "\n".join(tmp[0:tmp_n]))
        self.assertTrue(got_prompt, before_output + str(child.after))

    def test_CVE_2010_2956_zz_cleanup(self):
        '''Cleanup CVE-2010-2956 tests'''
        global escaper
        global geese

        # remove all timestamps for our users
        for i in [escaper.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        escaper = None
        geese = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

    def test_CVE_2011_0010_aa_setup(self):
        '''Setup CVE-2011-0010 tests'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        # confined can NOT become root via -u or -g
        # escaper can NOT become root via -u or -g
        global confined
        global escaper
        global geese

        geese = testlib.TestGroup()

        # confined not in geese
        confined = testlib.TestUser()

        # escaper in geese
        escaper = testlib.TestUser()
        escaper.add_to_group(geese.group)

        testlib.config_replace('/etc/sudoers','''
Defaults	!lecture,tty_tickets,!fqdn
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
%%%s ALL=(ALL:ALL) ALL
''' % (self.sudo_group, geese.group))
        os.chmod('/etc/sudoers', 0440)

    def test_CVE_2011_0010_bb_escalate(self):
        '''Test CVE-2011-0010'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        # user not in the geese group can't escalate via -g
        self._sudo_togroup_fromuser('root', confined.login, False)

        # user in the geese group can't escalate via -g
        self._sudo_togroup_fromuser("root", escaper.login, False)

        # user not in the geese group can't escalate via -u
        self._sudo_touser_fromuser('root', confined.login, False)

        # user in the geese group can't escalate via -u
        self._sudo_touser_fromuser('root', escaper.login, False)

    def test_CVE_2011_0010_zz_cleanup(self):
        '''Cleanup CVE-2011-0010 tests'''
        if self.lsb_release['Release'] < 9.10:
            return self._skipped("group Runas_List not supported")

        global confined
        global escaper
        global geese

        # remove all timestamps for our users
        for i in [escaper.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        confined = None
        escaper = None
        geese = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

    def test_CVE_2014_9680_aa_setup(self):
        '''Setup CVE-2014-9680 tests'''

        global confined
        confined = testlib.TestUser()
        confined.add_to_group(self.sudo_group)


    def test_CVE_2014_9680_bb_escalate(self):
        '''Test CVE-2014-9680'''

        global confined

        # remove all timestamps for our user
        if os.path.exists(os.path.join(self.rundir, confined.login)):
            testlib.recursive_rm(os.path.join(self.rundir, confined.login))

        # First try a clean TZ
        sudo_cmd = "TZ=/usr/share/zoneinfo/blah /usr/bin/sudo -S /usr/bin/printenv TZ"
        child = pexpect.spawn('/bin/su -c "%s" %s' % (sudo_cmd, confined.login),
                              timeout=2)

        was_prompted = False
        rc = True
        ret = child.expect([r'[Pp]assword',
                            pexpect.EOF,
                            pexpect.TIMEOUT])
        if ret > 0: # found EOF
            rc = False
        elif ret == 0: # prompted for a password
            time.sleep(0.2)
            child.sendline(confined.password)
            time.sleep(0.2)
            if child.expect(["/usr/share/zoneinfo/blah",
                             pexpect.EOF,
                             pexpect.TIMEOUT]) > 0:
                rc = False

        child.kill(0)
        self.assertTrue(rc == True, str(child.before) + str(child.after))

        # remove all timestamps for our user
        if os.path.exists(os.path.join(self.rundir, confined.login)):
            testlib.recursive_rm(os.path.join(self.rundir, confined.login))

        # Now try a dirty TZ
        sudo_cmd = "TZ=/root/blah /usr/bin/sudo -S /usr/bin/printenv TZ"
        child = pexpect.spawn('/bin/su -c "%s" %s' % (sudo_cmd, confined.login),
                              timeout=2)

        was_prompted = False
        rc = True
        ret = child.expect([r'[Pp]assword',
                            pexpect.EOF,
                            pexpect.TIMEOUT])

        if ret != 0:
            child.kill(0)

        # Make sure we get a password prompt
        self.assertTrue(ret == 0, str(child.before) + str(child.after))

        time.sleep(0.2)
        child.sendline(confined.password)
        time.sleep(0.2)
        ret = child.expect(["/root/blah",
                            pexpect.EOF,
                            pexpect.TIMEOUT])

        if ret == 0:
            child.kill(0)

        # Make sure we don't get the bad TZ back
        self.assertTrue(ret > 0, str(child.before) + str(child.after))

        child.kill(0)

    def test_CVE_2014_9680_zz_cleanup(self):
        '''Cleanup CVE-2014-9680 tests'''
        global confined

        # remove all timestamps for our user
        if os.path.exists(os.path.join(self.rundir, confined.login)):
            testlib.recursive_rm(os.path.join(self.rundir, confined.login))

        confined = None

class SudoTestUbuntu(testlib.TestlibCase):
    '''Test sudo with typical Ubuntu setup.'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.sudo_cmd = "/usr/bin/id"
        self.sudo_cmd_with_password = "/bin/ls /"
        self.tmpdir = ""
        self.prev_editor = ""
        self.prev_path = ""
        self.rundir = "/var/run/sudo"
        if self.lsb_release['Release'] >= 10.10:
            self.rundir = "/var/lib/sudo"
        self.sudo_group = sudo_group(self.lsb_release['Release'])
        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        # Do NOT restore the sudoers file here due to shared configurations
        # among different sets of tests.
        os.chdir(self.current_dir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        if self.prev_path != "":
            os.environ["PATH"] = self.prev_path

        # reset the user's timestamp
        for obj in [confined, outsider]:
            if obj != None:
                if os.path.exists(os.path.join(self.rundir, obj.login)):
                    testlib.recursive_rm(os.path.join(self.rundir, obj.login))

        if self.prev_editor != "":
            os.environ["EDITOR"] = self.prev_editor

    def _clear_timestamp(self, user, remove=True, sleep=None):
        '''Clear a user's timestamp'''
        flag = '-k'
        if remove:
            flag = '-K'
        rc, report = testlib.cmd(['su', '-c' 'sudo %s' % flag, confined.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)

        if sleep != None:
            time.sleep(sleep)

    def _run_sudo_command(self, sudo_args, cmd, frompass='', fromuser="root", touser="", expect=[], desired=True):
        '''Run command from one user to another.'''
        # env tests require absolute path
        # Need -S because su drops tty
        sudo_cmd = "/usr/bin/sudo -S %s" % sudo_args
        if touser != "":
            sudo_cmd += " -u %s" % touser
        sudo_cmd += " %s" % cmd

        # env tests require absolute path
        child = pexpect.spawn('/bin/su -c "%s" %s' % (sudo_cmd, fromuser), timeout=2)

	# See if we got what we expected, while also dealing with cached and
        # uncached passwords. This is slightly hard to follow: 
        was_prompted = False
        rc = True
        index = child.expect(expect + [r'[Pp]assword', pexpect.EOF, pexpect.TIMEOUT])
        # if index is past the number of elements in expect
        # and past the password prompt
        if index > len(expect):
            rc = False
        # else index is only past the number of elements in expect,
        # so it's the password prompt
        elif index == len(expect):
            was_prompted = True
            time.sleep(0.2)
            child.sendline(frompass)
            time.sleep(0.2)
            # Try and get the expect again
            if child.expect(expect + [pexpect.EOF,pexpect.TIMEOUT]) >= len(expect):
                rc = False

        child.kill(0)
        self.assertTrue(rc == desired, str(child.before) + str(child.after))

        return was_prompted

    def test_aa_setup(self):
        '''Setup environment for Ubuntu tests'''
        global confined
        global outsider
        confined = testlib.TestUser()
        outsider = testlib.TestUser()

        extra_defaults = ''
        if self.lsb_release['Release'] >= 11.04:
            # http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=596493
            extra_defaults = ',env_keep=HOME'

        testlib.config_replace('/etc/sudoers','''
Defaults	!lecture,tty_tickets,!fqdn%s
root   ALL=(ALL) ALL
%%%s ALL=(ALL) ALL
%s ALL=(ALL) NOPASSWD: %s
''' % (extra_defaults, self.sudo_group, confined.login, self.sudo_cmd))
        os.chmod('/etc/sudoers', 0440)

        testlib.cmd(['adduser', confined.login, self.sudo_group])

    def test_zz_cleanup(self):
        '''Cleanup Ubuntu tests'''
        global confined
        global outsider

        # remove all timestamps for our users
        for i in [confined.login, outsider.login]:
            if os.path.exists(os.path.join(self.rundir, i)):
                testlib.recursive_rm(os.path.join(self.rundir, i))

        testlib.cmd(['deluser', confined.login, 'admin'])

        confined = None
        outsider = None
        testlib.config_restore('/etc/sudoers')
        os.chmod('/etc/sudoers',0440)

    # this test doesn't work right now
    def _disabled_test_timestamps(self):
        '''Test timestamps'''
        # run it once to get it cached
        self._run_sudo_command('', self.sudo_cmd_with_password, confined.password, confined.login, '', ['etc'], True)

        # -K
        self._clear_timestamp(confined.login, remove=True, sleep=2)
        rc, report = testlib.cmd(['stat', '%s/%s/3' % (self.rundir, confined.login)])
        was_prompted = self._run_sudo_command('', self.sudo_cmd_with_password, confined.password, confined.login, '', ['etc'], True)
        self.assertTrue(was_prompted, "Was not prompted")
        was_prompted = self._run_sudo_command('', self.sudo_cmd_with_password, confined.password, confined.login, '', ['etc'], True)
        self.assertFalse(was_prompted, "Was prompted")

        # -k
        self._clear_timestamp(confined.login, remove=False, sleep=2)
        was_prompted = self._run_sudo_command('', self.sudo_cmd_with_password, confined.password, confined.login, '', ['etc'], True)
        self.assertTrue(was_prompted, "Was not prompted")
        was_prompted = self._run_sudo_command('', self.sudo_cmd_with_password, confined.password, confined.login, '', ['etc'], True)
        self.assertFalse(was_prompted, "Was prompted")

        # -v
        self._clear_timestamp(confined.login, remove=True, sleep=2)
        rc, report = testlib.cmd(['su', '-c' 'sudo -v', confined.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        was_prompted = self._run_sudo_command('', self.sudo_cmd_with_password, confined.password, confined.login, '', ['etc'], True)
        self.assertFalse(was_prompted, "Was prompted")

    def test_visudo(self):
        '''Test visudo'''
        if os.environ.has_key("EDITOR") and os.environ["EDITOR"] != "":
            self.prev_editor = os.environ["EDITOR"]

        os.environ["EDITOR"] = "cat"
        rc, report = testlib.cmd(['visudo'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue('unchanged' in report, result + report)

    def test_version_and_help(self):
        '''Test version and help'''
        rc, report = testlib.cmd(['sudo', '-h'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue('sage:' in report, result + report)

        rc, report = testlib.cmd(['sudo', '-V'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue('ersion' in report, result + report)

    def test_user(self):
        '''Test user'''
        self._run_sudo_command('', self.sudo_cmd, '', confined.login, outsider.login, [r'uid=[0-9]+\(%s\) ' % outsider.login], True)

        self._run_sudo_command('', self.sudo_cmd, outsider.password, outsider.login, confined.login, [r'uid=[0-9]+\(%s\) ' % confined.login], False)

    def test_list(self):
        '''Test list'''
        rc, report = testlib.cmd(['sudo', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        #self.assertTrue('root' in report, result + report)

        # -U not supported in sudo 1.6
        if self.lsb_release['Release'] < 9.10:
            return

        rc, report = testlib.cmd(['sudo', '-l', '-U', confined.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue(confined.login in report, result + report)
        self.assertTrue(self.sudo_cmd in report, result + report)

        rc, report = testlib.cmd(['sudo', '-l', '-U', outsider.login])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue(outsider.login in report, result + report)
        self.assertFalse(self.sudo_cmd in report, result + report)

    def test_list_defaults(self):
        '''Test list defaults'''
        if self.lsb_release['Release'] >= 12.04:
            return self._skipped("list defaults option is gone in 1.8.x")

        rc, report = testlib.cmd(['sudo', '-L'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertTrue(rc == expected, result + report)
        self.assertTrue('env_reset' in report, result + report)

    def test_home(self):
        '''Test home'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        script = os.path.join(self.tmpdir, "home.sh")
        contents = '''#!/bin/sh -e
echo "$HOME"
'''
        testlib.create_fill(script, contents, mode=0755)
        os.chmod(self.tmpdir, 0775)

        self._run_sudo_command('', script, confined.password, confined.login, '', [r'/root'], False)
        self._run_sudo_command('-H', script, confined.password, confined.login, '', [r'/root'], True)

    def test_groups(self):
        '''Test groups'''
        self._run_sudo_command('', self.sudo_cmd, '', confined.login, '', [r'[0-9]+\(%s\) ' % confined.login], False)
        self._run_sudo_command('-P', self.sudo_cmd, '', confined.login, '', [r'[0-9]+\(%s\) ' % confined.login], False)

    def test_commands(self):
        '''Test commands via sudo'''
        self._run_sudo_command(sudo_args = '',
                               cmd = 'cat /etc/sudoers',
                               frompass = confined.password,
                               fromuser = confined.login,
                               touser = '',
                               expect = ['%s' % confined.login],
                               desired = True)
        self._run_sudo_command(sudo_args = '',
                               cmd = 'cat /etc/sudoers',
                               frompass = confined.password,
                               fromuser = confined.login,
                               touser = '',
                               expect = ['%s' % outsider.login],
                               desired = False)
        self._run_sudo_command(sudo_args = '',
                               cmd = 'cat /etc/sudoers',
                               frompass = outsider.password,
                               fromuser = outsider.login,
                               touser = '',
                               expect = ['%s' % confined.login],
                               desired = False)

    def test_path(self):
        '''Test PATH (secure_path)'''
        test_exe = "testlib-foo"
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chmod(self.tmpdir, 0775)
        shutil.copy("/usr/bin/whoami", os.path.join(self.tmpdir, test_exe))
        os.chdir(self.tmpdir)

        # make sure test_exe works at all
        self._run_sudo_command('', os.path.join(self.tmpdir, test_exe), confined.password, confined.login, '', ['root'], True)

        # make sure our secure_path can find whoami
        self._run_sudo_command('', 'whoami', confined.password, confined.login, '', ['root'], True)

        if self.lsb_release['Release'] >= 8.04:
            # with -E, the PATH should be ignored due to secure_path
            self._run_sudo_command('-E PATH=/tmp', test_exe, confined.password, confined.login, '', ['root'], False)

        # with 'sudo PATH=/tmp', the PATH should be ignored due to secure_path
        self._run_sudo_command('PATH=/tmp', test_exe, confined.password, confined.login, '', ['root'], False)

        self.prev_path = os.environ["PATH"]
        os.environ["PATH"] = "/tmp"
	# with 'PATH=/tmp /usr/bin/sudo', the PATH should be ignored due to
        # secure_path
        self._run_sudo_command('', test_exe, confined.password, confined.login, '', ['root'], False)

    def test_env_merge(self):
        '''Test PAM environment merging'''
        var = "QRT_TEST_ENV_MERGE"
        merged = "merged"

        if self.lsb_release['Release'] < 12.04:
            return self._skipped("PAM environment merging not supported")

        if self.lsb_release['Release'] in [ 14.04, 14.10 ]:
            return self._skipped("PAM environment merging doesn't work")

        testlib.config_replace('/etc/environment', var + '=' + merged, True)
        self._run_sudo_command('', "/usr/bin/printenv " + var,
                               confined.password, confined.login, '', [merged],
                               True)
        testlib.config_restore('/etc/environment')

if __name__ == '__main__':
    testlib.require_sudo()
    suite = unittest.TestSuite()

    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SudoTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(SudoTestUbuntu))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)

    if not rc.wasSuccessful():
        sys.exit(1)
