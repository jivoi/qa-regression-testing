#!/usr/bin/python
#
#    test-backuppc.py quality assurance test script for backuppc
#    Copyright (C) 2011-2012 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: backuppc elinks
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: testlib_httpd.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-backuppc.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-backuppc.py -v'

    Setup
    - postfix may be installed. just choose internet site and all defaults)
    - choose apache2 (for now)
    - web interface http://<host>/backuppc/
'''


import unittest, subprocess, sys, os
import testlib
import testlib_httpd
import glob
import time
import urllib

try:
    from private.qrt.BackupPC import PrivateBackupPCTest
except ImportError:
    class PrivateBackupPCTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class BackupPCTest(testlib_httpd.HttpdCommon, PrivateBackupPCTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.htpasswd = '/etc/backuppc/htpasswd'
        self.username = "backuppc"
        self.password = "youcantguessme!;P"
        testlib.config_replace(self.htpasswd, "", True)
	self._update_htpasswd(user=self.username, password=self.password)

        self.topurl = "http://%s:%s@localhost/backuppc/" % (self.username, self.password)
        self.backupdir = "/var/lib/backuppc/pc"
        self.localhost_config = "/etc/backuppc/localhost.pl"

        # Later versions of backuppc fail without this --ignore-failed-read
        testlib.config_replace(self.localhost_config, "", True)
        subprocess.call(['sed', '-i', "s/ --totals/ --totals --ignore-failed-read/", self.localhost_config])

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib.config_restore(self.localhost_config)
        testlib.config_restore(self.htpasswd)

    def _find_latest_backup_num(self, host="localhost"):
        '''Find latest backup number'''
        topdir = os.path.join(self.backupdir, host)
        dirs = glob.glob("%s/[0-9]*" % topdir)
        if len(dirs) == 0:
            return -1

        backups = sorted(dirs, key=lambda k: int(os.path.basename(k)))
        return int(os.path.basename(backups[-1]))

    def _update_htpasswd(self, user="backuppc", password="pass"):
        '''Update the htpasswd file for backuppc'''
        cmd = ['htpasswd', '-b', '-m'] # batch and use md5 instead of crypt()
        if not os.path.exists(self.htpasswd):
             cmd.append('-c')
        cmd += [self.htpasswd, user, password]
        (rc, report) = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _check_backup(self, host="localhost", index=None, incremental=False):
        idx = index
        if index == None:
            idx = self._find_latest_backup_num(host)

        topdir = os.path.join(self.backupdir, host)
        files = [
                 topdir,
                 os.path.join(topdir, "backups"),
                 os.path.join(topdir, "%s/attrib" % str(idx)),
                 os.path.join(topdir, "%s/backupInfo" % str(idx)),
                 os.path.join(topdir, "%s/f%%2fetc" % str(idx)),
                ]

        previous_num = idx - 1
        if previous_num >= 0:
             os.path.join(topdir, "XferLOG.%d.z" % previous_num)
             os.path.join(topdir, "backups.old")

        for f in files:
             self.assertTrue(os.path.exists(f), "Could not find '%s'" % f)

        # This one sometimes takes longer to come up
        count = 0
        d = os.path.join(topdir, str(idx))
        while not os.path.exists(d) and count < 60:
            time.sleep(1)
            count += 1
        self.assertTrue(os.path.exists(d), "Could not find '%s' after 60 seconds" % d)

        backup_info = os.path.join(topdir, "%s/backupInfo" % str(idx))
        info = open(backup_info).read()

        searches = ["%backupInfo", "'size' =>", "'xferMethod' => 'tar'"]
        if incremental:
            self.assertFalse("'level' => '0'" in info, "Found 'level 0' in:\n%s" % info)
        else:
            searches.append("'level' => '0'")

        for s in searches:
            if s == "'level' => '0'": # the very first run is: 'level' => 0. Account for that
                self.assertTrue(s in info or "'level' => 0" in info, "Could not find '%s' in:\n%s" % (s, info))
            else:
                self.assertTrue(s in info, "Could not find '%s' in:\n%s" % (s, info))

    def _search_log(self, logfile, search):
        '''Search log for string'''
        self.assertTrue(os.path.exists(logfile), "Could not find '%s'" % logfile)
        log = ""
        if logfile.endswith(".z"): # unzip
            rc, log = testlib.cmd(['/usr/share/backuppc/bin/BackupPC_zcat', logfile])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + log)
        else:
            log = open(logfile).read()
        return search in log

    def _trigger_backup(self, host="localhost", incremental=False):
        '''Trigger a backup'''
        action = "Start_Full_Backup"
        if incremental:
            action = "Start_Incr_Backup"

        current_idx = self._find_latest_backup_num()
        url = "%s/index.cgi?host=%s&hostIP=%s&doit=1&action=%s" % (self.topurl, host, host, action)
        self._test_url(url, "Reply from server was: ok: requested backup of %s" % host)

        next_idx = current_idx + 1 # assumes _find_latest_backup_num() returns
                                   # -1 on error
        ext = ".z"
        if self.lsb_release['Release'] < 10.04:
            ext = ""
        next_log = os.path.join(self.backupdir, host, "XferLOG.%d%s" % (next_idx, ext))

        count = 0
        done = False
        while not done and count < 30:
            if os.path.exists(next_log):
                done = self._search_log(next_log, ": Done: ")
            time.sleep(1)
            count += 1

        self._check_backup(host="localhost", index=next_idx, incremental=incremental)

    def test_aa_trigger_backup(self):
        '''Test trigger first full backup'''
        self._trigger_backup()

    def test_bb_basic_auth(self):
        '''Test basic auth'''
        self._test_url("http://localhost/backuppc/", "Authorization Required")

    def test_bb_home(self):
        '''Test home page'''
        self._test_url(self.topurl, "BackupPC Server Status")

    def test_summary(self):
        '''Test summary page'''
        searches = [
                    "BackupPC: Host Summary",
                    "Hosts with good Backups",
                    "There are 1 hosts that have been backed up",
                    "Hosts with no Backups",
                    "There are 0 hosts with no backups.",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=summary" % self.topurl, s)

    def test_edit_config(self):
        '''Test edit config page'''
        searches = [
                    "Main Configuration Editor",
                    "General Parameters",
                    "Wakeup Schedule",
                    "Concurrent Jobs",
                    "Pool Filesystem Limits",
                    "Other Parameters",
                    "Remote Apache Settings",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=editConfig" % self.topurl, s)

    def test_edit_hosts(self):
        '''Test edit hosts page'''
        searches = [
                    "Main Configuration Editor",
                    "Hosts",
                    "localhost",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=editConfig&newMenu=hosts" % self.topurl, s)

    def test_admin_options(self):
        '''Test admin options page'''
        searches = [
                    "Admin Options",
                    "Server Control",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=adminOpts" % self.topurl, s)

    def test_log_file(self):
        '''Test log file page'''
        searches = [
                    "File /var/lib/backuppc/log/LOG",
                    "Reading hosts file",
                    "localhost to backup list",
                    "BackupPC started, pid",
                    "Next wakeup",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=view&type=LOG" % self.topurl, s)

    def test_log_file_old(self):
        '''Test old log file page'''
        searches = [
                    "Log File History",
                    "LOG",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=LOGlist" % self.topurl, s)

    def test_email_summary(self):
        '''Test email summary page'''
        searches = [
                    "Recent Email Summary",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=emailSummary" % self.topurl, s)

    def test_current_queues(self):
        '''Test current queues page'''
        searches = [
                    "Backup Queue Summary",
                    "User Queue Summary",
                    "Command Queue Summary",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=queue" % self.topurl, s)

    def test_documentation(self):
        '''Test documentation page'''
        searches = [
                    "BackupPC Introduction",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=view&type=docs" % self.topurl, s)

    def test_localhost_home(self):
        '''Test localhost home page'''
        searches = [
                    "Host localhost Backup Summary",
                    "This PC is used by",
                    "Last status is state",
                    "Pings to localhost have succeeded",
                    "User Actions",
                    "Backup Summary",
                    "Xfer Error Summary",
                    "Count Reuse Summary",
                    "Compression Summary",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?host=localhost" % self.topurl, s)

    def test_localhost_backup(self):
        '''Test localhost backup page'''
        backup_num = self._find_latest_backup_num()
        self.assertTrue(backup_num >= 0, "No backups found!")
        searches = [
                    "Backup browse for localhost",
                    "You are browsing backup #%d, which started around" % backup_num,
                    "Select the backup you wish to view",
                    "Contents of /etc",
                    "=/passwd",
                    "dir=/backuppc",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=browse&host=localhost&num=%d" % (self.topurl, backup_num), s)

        # this should not be downloadable
        inverted_searches = [
                             "=/shadow",
                            ]
        for s in inverted_searches:
            self._test_url("%s/index.cgi?action=browse&host=localhost&num=%d" % (self.topurl, backup_num), s, invert=True)

    def test_localhost_log_xfer(self):
        '''Test localhost backup xfer log'''
        backup_num = self._find_latest_backup_num()
        self.assertTrue(backup_num >= 0, "No backups found!")

        ext = ".z"
        if self.lsb_release['Release'] < 10.04:
            ext = ""

        searches = [
                    "File /var/lib/backuppc/pc/localhost/XferLOG.%d%s" % (backup_num, ext),
                    "create   755       0/0           0 cron.d",
                    "Contents of file /var/lib/backuppc/pc/localhost/XferLOG.%d%s, modified" % (backup_num, ext),
                    "Done: 0 errors",
                   ]
        for s in searches:
            self._test_url("%s/index.cgi?action=view&type=XferLOG&num=%d&host=localhost" % (self.topurl, backup_num), s)

    def test_localhost_backup_errors(self):
        '''Test localhost backup errors'''
        backup_num = self._find_latest_backup_num()
        self.assertTrue(backup_num >= 0, "No backups found!")
        ext = ".z"
        if self.lsb_release['Release'] < 10.04:
            ext = ""
        searches = [
                    "File /var/lib/backuppc/pc/localhost/XferLOG.%d%s (Extracting only Errors)" % (backup_num, ext),
                    "Contents of file /var/lib/backuppc/pc/localhost/XferLOG.%d%s, modified" % (backup_num, ext),
                    "./shadow: Warning: Cannot open: Permission denied",
                   ]

        for s in searches:
            self._test_url("%s/index.cgi?action=view&type=XferErr&num=%d&host=localhost" % (self.topurl, backup_num), s)

    def test_localhost_restore_file(self):
        '''Test localhost restore file'''
        backup_num = self._find_latest_backup_num()
        self.assertTrue(backup_num >= 0, "No backups found!")
        self._test_url("%s/index.cgi?action=RestoreFile&host=localhost&num=%d&share=/etc&dir=/hosts" % (self.topurl, backup_num), '127.0.0.1')

    def test_nonexistent(self):
        '''Test nonexistent page'''
        searches = [
                    "Not Found",
                   ]
        for s in searches:
            self._test_url("%s/nonexistent" % self.topurl, s)

    def test_yy_trigger_incremental_backup(self):
        '''Test trigger incremental backup'''
        self._trigger_backup(incremental=True)

    def test_zz_trigger_backup(self):
        '''Test trigger second full backup'''
        self._trigger_backup()

    def test_zzz_CVE_2011_3361(self):
        '''Test CVE-2011-3361 (CGI/Browse.pm)'''
        search = '<script>alert("gotcha");</script>'
        actions = [
                   'browse&host=localhost&num=%s' % urllib.quote_plus(search),
                  ]
        for a in actions:
            url = "%s/index.cgi?action=%s" % (self.topurl, a)
            self._test_url(url, search, invert=True, source=True)

    def test_zzz_CVE_2011_4923(self):
        '''Test CVE-2011-4923 (CGI/View.pm)'''
        search = '<script>alert("gotcha");</script>'
        actions = [
                   'view&type=XferLOG&num=%s&host=localhost' % urllib.quote_plus(search),
                   'view&type=XferErr&num=%s&host=localhost' % urllib.quote_plus(search),
                  ]
        for a in actions:
            url = "%s/index.cgi?action=%s" % (self.topurl, a)
            self._test_url(url, search, invert=True, source=True)

    def test_zzz_CVE_2011_5081(self):
        '''Test CVE-2011-5081 (CGI/RestoreFile.pm)'''
        search = '<script>alert("gotcha");</script>'
        actions = [
                   'RestoreFile&host=localhost&num=1&share=%s&dir=' % urllib.quote_plus(search),
                   'RestoreFile&host=localhost&num=%s&share=234&dir=' % urllib.quote_plus(search),
                  ]
        for a in actions:
            url = "%s/index.cgi?action=%s" % (self.topurl, a)
            self._test_url(url, search, invert=True, source=True)

    # Uncomment this for testing new problems
    #def test_zzzz_stub(self):
    #    '''Test stub'''
    #    subprocess.call(['bash'])


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BackupPCTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
