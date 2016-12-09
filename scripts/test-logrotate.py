#!/usr/bin/python
#
#    test-logrotate.py quality assurance test script for logrotate
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: logrotate
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends:
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install lsb-release <QRT-Packages> && sudo ./test-logrotate.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-logrotate.py -v'
'''


import unittest, sys, os, tempfile, pwd, stat
import testlib

try:
    from private.qrt.logrotate import PrivateLogrotateTest
except ImportError:
    class PrivateLogrotateTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LogrotateTest(testlib.TestlibCase, PrivateLogrotateTest):
    '''Test logrotate.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="logrotate-")
        self.state_file = os.path.join(self.tempdir, 'state')
        self.config_file = os.path.join(self.tempdir, 'config')
        self.mailer_script = os.path.join(self.tempdir, 'mailer')
        self.mailer_output = os.path.join(self.tempdir, 'mailer-output')
        self.current_dir = os.getcwd()
        self._create_mailer()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if self.current_dir != os.getcwd():
            os.chdir(self.current_dir)

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _create_mailer(self):
        '''Creates a mailer script'''
        open(self.mailer_script,'w').write('''#!/bin/bash

echo "$*" > %s
cat >> %s''' % (self.mailer_output, self.mailer_output))
        os.chmod(self.mailer_script, 0755)

    def _preptest(self, base_name, number, compressed=False):
        '''Prepares logrotate directory'''
        for lognum in range(number):
            if lognum == 0:
                self._createlog(0, base_name)
            else:
                self._createlog(lognum, "%s.%s" % (base_name, lognum), compressed)

    def _createlog(self, number, log_name, compressed=False):
        '''Create a log file with some contents'''

        contents = [ 'zero', 'first', 'second', 'third', 'fourth', 'fifth',
                    'sixth', 'seventh', 'eight', 'ninth' ]

        full_log_name = os.path.join(self.tempdir, log_name)
        open(full_log_name,'w').write(contents[number])

        if compressed == True:
            rc, report = testlib.cmd(['gzip', '-9', full_log_name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def _prepconfig(self, config):
        '''Prepares config file'''
        open(self.config_file,'w').write(config)

    def _prepstate(self, state):
        '''Prepares state file'''
        open(self.state_file,'w').write(state)

    def _createfile(self, filename, contents):
        '''Creates a new file'''
        full_filename = os.path.join(self.tempdir, filename)
        open(full_filename,'w').write(contents)

    def _run_logrotate(self, force=True):
        '''Runs logrotate'''
        cmd = ['/usr/sbin/logrotate', '-m', self.mailer_script, '-s', self.state_file, self.config_file]
        if force == True:
            cmd.append('--force')

        os.chdir(self.tempdir)
        rc, report = testlib.cmd(cmd)
        os.chdir(self.current_dir)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _checkoutput(self, output_files):
        '''Checks the resulting files'''
        for (name, compressed, expected) in output_files:
            full_name = os.path.join(self.tempdir, name)

            error = 'Could not find file "%s"' % name
            self.assertTrue(os.path.exists(full_name), error)

            if compressed == True:
                rc, contents = testlib.cmd(['gunzip', '-c', full_name])
            else:
                contents = open(full_name).read()

            error = "File '%s' contents aren't what was expected: expected '%s', found '%s'." % (name, expected, contents)
            self.assertEqual(expected, contents, error)

    def _checkmail(self, log_name, expected):
        '''Checks the contents of the mailer output file'''
        full_name = os.path.join(self.tempdir, log_name)
        expected_contents = '''-s %s user@myhost.org
%s''' % (full_name, expected)

        contents = open(self.mailer_output).read()

        error = "Mailer contents aren't what was expected: expected '%s', found '%s'." % (expected_contents, contents)
        self.assertEqual(expected_contents, contents, error)

    def _checkextra(self, extra_file):
        '''Checks for an extra file'''
        extra_filename = os.path.join(self.tempdir, extra_file)
        error = "Found extra file: '%s'." % extra_filename
        self.assertFalse(os.path.exists(extra_filename), error)

    # The following numbered tests are based on the test suite that
    # comes with logrotate

    def test_1(self):
        '''Test 1'''

        self._preptest('test.log', 2)
        self._prepconfig('''
create

%s/test.log {
    daily
    # note the white space after this line
    rotate 2 
    mail user@myhost.org
    maillast
}''' % self.tempdir)

        # Without a state file, no rotations should occur
        self._run_logrotate(force=False)

        output_files = [ [ 'test.log',   False, 'zero' ],
                         [ 'test.log.1', False, 'first' ] ]

        self._checkoutput(output_files)

        # Now try with a state file
        self._prepstate('''logrotate state -- version 1
"%s/test.log" 2000-1-1
''' % self.tempdir)
        self._run_logrotate(force=False)

        output_files = [ [ 'test.log',   False, '' ],
                         [ 'test.log.1', False, 'zero' ],
                         [ 'test.log.2', False, 'first' ] ]

        self._checkoutput(output_files)

        # Rerun it to make sure nothing happens
        self._run_logrotate(force=False)
        self._checkoutput(output_files)

    def test_2(self):
        '''Test 2'''

        self._preptest('test.log', 3)
        self._prepconfig('''
"%s/test.log" {
    monthly
    rotate 2
    mail user@myhost.org
    maillast
}''' % self.tempdir)

        self._run_logrotate()

        output_files = [ [ 'test.log.1', False, 'zero' ],
                         [ 'test.log.2', False, 'first' ] ]

        self._checkoutput(output_files)
        self._checkmail('test.log.3', 'second')

        # Make sure it properly removed the old log
        self._checkextra('test.log')

    def test_3(self):
        '''Test 3'''

        self._preptest('test.log', 1)
        self._prepconfig('''
create

%s/test*.log {
    monthly
    rotate 1
    mail user@myhost.org
    maillast

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % self.tempdir)

        self._run_logrotate()

        output_files = [ [ 'test.log',   False, '' ],
                         [ 'test.log.1', False, 'zero' ],
                         [ 'scriptout',  False, 'foo\n' ] ]

        self._checkoutput(output_files)

    def test_3b(self):
        '''Test 3b'''

        self._preptest('test.log', 1)
        self._preptest('test2.log', 1)
        self._prepconfig('''
create

%s/test*.log {
    monthly
    rotate 1
    mail user@myhost.org
    maillast

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % self.tempdir)

        self._run_logrotate()

        output_files = [ [ 'test.log',    False, '' ],
                         [ 'test.log.1',  False, 'zero' ],
                         [ 'test2.log',   False, '' ],
                         [ 'test2.log.1', False, 'zero' ],
                         [ 'scriptout',   False, 'foo foo\n' ] ]

        self._checkoutput(output_files)

    def test_4(self):
        '''Test 4'''

        self._preptest('test.log', 1)
        self._preptest('test2.log', 1)
        self._prepconfig('''
create

%s/test*.log {
    monthly
    rotate 1
    mail user@myhost.org
    maillast
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % self.tempdir)

        self._run_logrotate()

        output_files = [ [ 'test.log',    False, '' ],
                         [ 'test.log.1',  False, 'zero' ],
                         [ 'test2.log',   False, '' ],
                         [ 'test2.log.1', False, 'zero' ],
                         [ 'scriptout',   False, 'foo\n' ] ]

        self._checkoutput(output_files)

    def test_5(self):
        '''Test 5'''

        self._preptest('test.log', 1)
        self._preptest('anothertest.log', 1)
        self._prepconfig('''
create

%s/test.log %s/anothertest.log {
    monthly
    rotate 1
    mail user@myhost.org
    maillast
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % (self.tempdir, self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',          False, '' ],
                         [ 'test.log.1',        False, 'zero' ],
                         [ 'anothertest.log',   False, '' ],
                         [ 'anothertest.log.1', False, 'zero' ],
                         [ 'scriptout',         False, 'foo\n' ] ]

        self._checkoutput(output_files)

    def test_6(self):
        '''Test 6'''

        self._preptest('test.log', 1)
        self._preptest('anothertest.log', 1)
        self._prepconfig('''
create

%s/test.log %s/anothertest.log {
    monthly
    rotate 1
    start 0
    mail user@myhost.org
    maillast
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % (self.tempdir, self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',          False, '' ],
                         [ 'test.log.0',        False, 'zero' ],
                         [ 'anothertest.log',   False, '' ],
                         [ 'anothertest.log.0', False, 'zero' ],
                         [ 'scriptout',         False, 'foo\n' ] ]

        self._checkoutput(output_files)

    def test_7(self):
        '''Test 7'''

        self._preptest('test.log', 1)
        self._preptest('anothertest.log', 1)
        self._prepconfig('''
create

%s/test.log %s/anothertest.log {
    monthly
    rotate 3
    start 6
    mail user@myhost.org
    maillast
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % (self.tempdir, self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',          False, '' ],
                         [ 'test.log.6',        False, 'zero' ],
                         [ 'anothertest.log',   False, '' ],
                         [ 'anothertest.log.6', False, 'zero' ],
                         [ 'scriptout',         False, 'foo\n' ] ]

        self._checkoutput(output_files)

    def test_8(self):
        '''Test 8'''

        self._preptest('test.log', 1, True)
        self._prepconfig('''
create

compress

%s/test.log {
    monthly
    rotate 3
    mail user@myhost.org
    mailfirst
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % (self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',      False, '' ],
                         [ 'test.log.1.gz', True,  'zero' ],
                         [ 'scriptout',     False, 'foo\n' ] ]

        self._checkoutput(output_files)
        self._checkmail('test.log', 'zero')

    def test_9(self):
        '''Test 9'''

        self._preptest('test.log', 1, True)
        self._prepconfig('''
create

compress

%s/test.log {
    monthly
    rotate 0
    mail user@myhost.org
    mailfirst
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % (self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',      False, '' ],
                         [ 'scriptout',     False, 'foo\n' ] ]

        self._checkoutput(output_files)
        self._checkmail('test.log', 'zero')

    def test_10(self):
        '''Test 10'''

        self._preptest('test.log', 1)
        self._prepconfig('''
create

%s/test.log {
    daily
    rotate 3
    compress
    delaycompress
    create
    mailfirst
    mail user@myhost.org
}''' % (self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',   False, '' ],
                         [ 'test.log.1', False, 'zero' ] ]

        self._checkoutput(output_files)

        self._createfile('test.log', 'newfile')
        self._run_logrotate()

        output_files = [ [ 'test.log',      False, '' ],
                         [ 'test.log.1',    False, 'newfile' ],
                         [ 'test.log.2.gz', True,  'zero' ] ]

        self._checkoutput(output_files)

        self._checkmail('test.log.1', 'newfile')

    def test_11(self):
        '''Test 11'''

        self._preptest('test.log', 1, True)
        self._prepconfig('''
create

compress

%s/test.log {
    monthly
    rotate 0
    mail user@myhost.org
    mailfirst
    sharedscripts

    postrotate
	touch scriptout
	echo $(cat scriptout) foo > foo
	mv foo scriptout
    endscript
}''' % (self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',      False, '' ],
                         [ 'scriptout',     False, 'foo\n' ] ]

        self._checkoutput(output_files)
        self._checkmail('test.log', 'zero')

    def test_12(self):
        '''Test 12'''

        # check rotation into a directory given as a relative pathname

        os.mkdir(os.path.join(self.tempdir,'testdir'))

        self._preptest('test.log', 1)
        self._prepconfig('''
create

%s/test.log {
    monthly
    rotate 1
    olddir testdir
}''' % (self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',           False, '' ],
                         [ 'testdir/test.log.1', False, 'zero' ] ]

        self._checkoutput(output_files)

    def test_13(self):
        '''Test 13'''

        # check rotation into a directory given as an absolute  pathname

        os.mkdir(os.path.join(self.tempdir,'testdir'))

        self._preptest('test.log', 1)
        self._prepconfig('''
create

%s/test.log {
    monthly
    rotate 1
    olddir %s/testdir
}''' % (self.tempdir, self.tempdir))

        self._run_logrotate()

        output_files = [ [ 'test.log',           False, '' ],
                         [ 'testdir/test.log.1', False, 'zero' ] ]

        self._checkoutput(output_files)

    def test_14(self):
        '''Test 14'''

        # sanity rotation check using dateext and dateformat

        self._preptest('test.log', 1)
        self._prepconfig('''
create

%s/test.log {
    daily
	dateext
	dateformat .%%Y-%%m-%%d
    rotate 1
}''' % (self.tempdir))

        # Hardy only has dateext
        if self.lsb_release['Release'] == 8.04:
            rc, datestring = testlib.cmd(['/bin/date', '+-%Y%m%d'])
        else:
            rc, datestring = testlib.cmd(['/bin/date', '+.%Y-%m-%d'])
        datestring = datestring.rstrip()

        self._run_logrotate()

        output_files = [ [ 'test.log', False, '' ],
                         [ 'test.log%s' % datestring, False, 'zero' ] ]

        self._checkoutput(output_files)

    def test_15(self):
        '''Test 15'''

        if self.lsb_release['Release'] < 10.04:
            return self._skipped("shred option not available (needs logrotate >= 3.7.5)")

        os.mkdir(os.path.join(self.tempdir,'testdir'))

        self._preptest('test.log', 1)
        self._prepconfig('''
create

%s/test.log {
    daily
    shred
    shredcycles 20
    rotate 1
}''' % (self.tempdir))

        self._run_logrotate()
        # this rotation should use shred
        self._run_logrotate()

        output_files = [ [ 'test.log',   False, '' ],
                         [ 'test.log.1', False, '' ] ]

        self._checkoutput(output_files)

    def test_perms_1(self):
        '''Test file permissions - 1'''

        self._preptest('test.log', 2)

        # Set specific owner and permissions so we can check later
        uid = pwd.getpwnam("lp")[2]
        gid = pwd.getpwnam("lp")[3]
        perms = 0700

        for logfile in ['test.log', 'test.log.1']:
            os.chown(os.path.join(self.tempdir, logfile), uid, gid)
            os.chmod(os.path.join(self.tempdir, logfile), perms)

        self._prepconfig('''
"%s/test.log" {
    monthly
    create
    rotate 2
    mail user@myhost.org
    maillast
}''' % self.tempdir)

        self._run_logrotate()

        output_files = [ [ 'test.log', False, '' ],
                         [ 'test.log.1', False, 'zero' ],
                         [ 'test.log.2', False, 'first' ] ]

        self._checkoutput(output_files)

        # Check permissions and owner
        for logfile in ['test.log', 'test.log.1', 'test.log.2']:
            st = os.stat(os.path.join(self.tempdir, logfile))
            error = "Uid doesn't match!: expecting '%s', got '%s'." % (uid, st[4])
            self.assertEqual(uid, st[4], error)
            error = "Gid doesn't match!: expecting '%s', got '%s'." % (gid, st[5])
            self.assertEqual(gid, st[5], error)
            error = "Permissions don't match!: expecting '%s', got '%s'." % (perms, stat.S_IMODE(st[0]))
            self.assertEqual(perms, stat.S_IMODE(st[0]), error)

    def test_perms_2(self):
        '''Test file permissions - 2'''

        self._preptest('test.log', 2)

        # Set specific owner and permissions so we can check later
        uid = pwd.getpwnam("lp")[2]
        gid = pwd.getpwnam("lp")[3]
        perms = 0700

        for logfile in ['test.log', 'test.log.1']:
            os.chown(os.path.join(self.tempdir, logfile), uid, gid)
            os.chmod(os.path.join(self.tempdir, logfile), perms)

        self._prepconfig('''
"%s/test.log" {
    monthly
    create 0770 root root
    rotate 2
    mail user@myhost.org
    maillast
}''' % self.tempdir)

        self._run_logrotate()

        output_files = [ [ 'test.log', False, '' ],
                         [ 'test.log.1', False, 'zero' ],
                         [ 'test.log.2', False, 'first' ] ]

        self._checkoutput(output_files)

        # Check permissions and owner on old logs
        for logfile in ['test.log.1', 'test.log.2']:
            st = os.stat(os.path.join(self.tempdir, logfile))
            error = "Uid doesn't match!: expecting '%s', got '%s'." % (uid, st[4])
            self.assertEqual(uid, st[4], error)
            error = "Gid doesn't match!: expecting '%s', got '%s'." % (gid, st[5])
            self.assertEqual(gid, st[5], error)
            error = "Permissions don't match!: expecting '%s', got '%s'." % (perms, stat.S_IMODE(st[0]))
            self.assertEqual(perms, stat.S_IMODE(st[0]), error)

        # Check permissions and owner on new log
        st = os.stat(os.path.join(self.tempdir, 'test.log'))
        error = "Uid doesn't match!: expecting '%s', got '%s'." % (0, st[4])
        self.assertEqual(0, st[4], error)
        error = "Gid doesn't match!: expecting '%s', got '%s'." % (0, st[5])
        self.assertEqual(0, st[5], error)
        error = "Permissions don't match!: expecting '%s', got '%s'." % (0770, stat.S_IMODE(st[0]))
        self.assertEqual(0770, stat.S_IMODE(st[0]), error)

    def test_cve_2011_1155(self):
        '''Test CVE-2011-1155'''

        # A file with a newline should corrupt the state file, making
        # logrotate refuse to run anymore

        self._preptest('test\ntest.log', 1)
        self._prepconfig('''
create

%s/* {
    daily
    rotate 1
}''' % (self.tempdir))

        self._run_logrotate()
        # Try again, now with corrupted logfile
        self._run_logrotate()


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
