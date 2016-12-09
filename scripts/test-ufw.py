#!/usr/bin/python
#
#    test-ufw.py quality assurance test script for ufw
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
# QRT-Packages: ufw pyflakes build-essential
# QRT-Depends: ufw
# QRT-Privilege: root
# QRT-Alternates: python-ufw:!precise python-ufw:!lucid

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-ufw.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-ufw.py -v'
'''


import unittest, subprocess, sys, os
import glob
import testlib
import tempfile

#try:
#    from private.qrt.Pkg import PrivatePkgTest
#except ImportError:
#    class PrivatePkgTest(object):
#        '''Empty class'''
#    print >>sys.stdout, "Skipping private tests"

class UfwCommon(testlib.TestlibCase):
    '''Common test cases'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        # useful for running in a VM
        for exe in ['iptables', 'ip6tables']:
            testlib.cmd([exe, '-I', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'])

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self._reset()

    def _flush_firewall(self):
        '''Flush firewall'''
        if os.path.exists('/lib/ufw/ufw-init'):
            testlib.cmd(['/lib/ufw/ufw-init', 'flush-all'])
        else:
            # based on '/lib/ufw/ufw-init flush-all'
            for exe in ['iptables', 'ip6tables']:
                testlib.cmd([exe, '-F'])
                testlib.cmd([exe, '-X'])
                testlib.cmd([exe, '-P', 'INPUT', 'ACCEPT'])
                testlib.cmd([exe, '-P', 'OUTPUT', 'ACCEPT'])
                testlib.cmd([exe, '-P', 'FORWARD', 'ACCEPT'])

                # Mangle table
                rc, report = testlib.cmd([exe, '-L', '-t', 'mangle'])
                if rc != 0:
                    continue
                for mangle_chain in ['INPUT', 'OUTPUT', 'FORWARD', 'PREROUTING', 'POSTROUTING']:
                    testlib.cmd([exe, '-t', 'mangle', '-F', mangle_chain])
                    testlib.cmd([exe, '-t', 'mangle', '-P', mangle_chain, 'ACCEPT'])

                # Nat table
                rc, report = testlib.cmd([exe, '-L', '-t', 'nat'])
                for nat_chain in ['OUTPUT', 'PREROUTING', 'POSTROUTING']:
                    testlib.cmd([exe, '-t', 'nat', '-F', mangle_chain])
                    testlib.cmd([exe, '-t', 'nat', '-P', mangle_chain, 'ACCEPT'])

    def _reset(self):
        '''Flush firewall'''
        self._flush_firewall()
        testlib.cmd(['ufw', 'disable'])


class UfwTest(UfwCommon):
    '''Test ufw (basic functions-- most covered by the test suites)'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib._restore_backup("/sbin/ip6tables")
        testlib.config_restore("/etc/default/ufw")
        self._tearDown()

    def _search_status(self, search):
        '''Test search status'''
        rc, report = testlib.cmd(['ufw', 'status', 'verbose'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def _enable(self):
        '''Enable the firewall'''
        args = ['ufw']
        if self.lsb_release['Release'] >= 10.04:
            args.append('--force')
        args.append('enable')

        rc, report = testlib.cmd(args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'Status: active'
        if self.lsb_release['Release'] < 9.04:
            search = "Firewall loaded"
        self._search_status(search)

    def _disable(self):
        '''Disable the firewall'''
        rc, report = testlib.cmd(['ufw', 'disable'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'Status: inactive'
        if self.lsb_release['Release'] < 9.04:
            search = "Firewall not loaded"
        self._search_status(search)

    def test_enable_disable(self):
        '''Test enable/disable'''
        self._enable()
        self._disable()

    def test_service(self):
        '''Test service/proto'''
        self._enable()

        rc, report = testlib.cmd(['ufw', 'allow', 'ssh/tcp'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = '22/tcp'
        if self.lsb_release['Release'] < 8.10:
            search = '22:tcp'
        self._search_status(search)

    def test_logging(self):
        '''Test logging'''
        self._enable()

        rc, report = testlib.cmd(['ufw', 'logging', 'on'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "Logging enabled"
        self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        if self.lsb_release['Release'] >= 8.10:
            search = 'Logging: on'
            self._search_status(search)

        rc, report = testlib.cmd(['ufw', 'logging', 'off'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = "Logging disabled"
        self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        if self.lsb_release['Release'] >= 8.10:
            search = 'Logging: off'
            self._search_status(search)

    def test_lp1039729(self):
        '''Test LP: #1039729'''
        testlib._save_backup("/sbin/ip6tables")
        os.unlink("/sbin/ip6tables")
        testlib._save_backup("/etc/default/ufw")
        subprocess.call(['sed', '-i', 's/^IPV6=yes/IPV6=no/', "/etc/default/ufw"])
        self._disable()
        self._enable()
        self._disable()
        rc, report = testlib.cmd(['ufw', 'app', 'update', 'all'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class UfwTestsuite(UfwCommon):
    '''Test ufw testsuite'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = None
        self.builder = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        self._tearDown()

    def _run_test(self, test, runas, search_terms, python="python"):
        '''Run specific testsuite test'''
        build_dir = testlib.prepare_source('ufw', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        os.chdir(build_dir)

        user_args = []
        if runas == 'non-root':
            user_args = ['sudo', '-u', self.builder.login]

        test_args = []
        if test == "non-root":
            test_args = ['./run_tests.sh', '-s', '-i', python]
        elif test == "root":
            test_args = ['./run_tests.sh', '-s', '-i', python, 'root']
        elif test == 'syntax-check':
            rc, report = testlib.cmd(['grep', test, './Makefile'])
            if rc == 0:
                test_args = ['make', test]
        elif test == 'man-check':
            rc, report = testlib.cmd(['grep', test, './Makefile'])
            if rc == 0:
                test_args = ['make', test]

        if len(test_args) == 0:
            return self._skipped("Skipped: TODO")

        print ""
        print "  make clean"
        rc, report = testlib.cmd(user_args + ['make', 'clean'])

        print "  %s (may take a while)" % (" ".join(test_args))
        rc, report = testlib.cmd(user_args + test_args)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Useful to see if failure
        #print report

        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))
        self.assertFalse('FAIL' in report, "Found 'FAIL' in:\n%s" % (report))

        # Newer versions of ufw added capabilities tests. Lets make sure the
        # test chain is not present
        if test == "root":
            for exe in ['iptables', 'ip6tables' ]:
                rc, report = testlib.cmd([exe, '-L', '-n'])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)
                search = 'caps-test'
                self.assertFalse(search in report, "Found '%s' in:\n%s" % (search, report))

        return report

    def test_man_check(self):
        '''Test ufw (man-check)'''
        self._run_test('man-check', 'non-root', ['PASS'])

    def test_syntax_check(self):
        '''Test ufw (syntax-check)'''
        self._run_test('syntax-check', 'non-root', [])

    def test_non_root(self):
        '''Test ufw (non-root)'''
        search_terms = ['PASS']

        # errors
        if self.lsb_release['Release'] < 8.10:
            search_terms.append('Errors:        0')
        else:
            search_terms.append('Errors:              0')

        # skipped tests
        if self.lsb_release['Release'] < 8.10:
            search_terms.append('Skipped:       0')
        elif self.lsb_release['Release'] >= 10.04 and self.lsb_release['Release'] < 10.10:
            search_terms.append('Skipped:             1\n')
        else:
            search_terms.append('Skipped:             0')

        self._run_test('non-root', 'non-root', search_terms, "python")

    def test_non_root_python3(self):
        '''Test ufw (non-root with python3)'''
        if self.lsb_release['Release'] < 12.10:
            return self._skipped("Python3 supported only in 12.10 and later")

        search_terms = ['PASS']
        search_terms.append('Errors:              0')
        search_terms.append('Skipped:             0')

        self._run_test('non-root', 'non-root', search_terms, "python3")

    def test_root(self):
        '''Test ufw (root)'''
        search_terms = ['PASS', 'Skipped:             0', 'Errors:              0']
        if self.lsb_release['Release'] < 8.10:
            search_terms = ['PASS', 'Skipped:       0', 'Errors:        0']

        self._run_test('root', 'root', search_terms, "python")

    def test_root_python3(self):
        '''Test ufw (root with python3)'''
        if self.lsb_release['Release'] < 12.10:
            return self._skipped("Python3 supported only in 12.10 and later")

        search_terms = ['PASS', 'Skipped:             0', 'Errors:              0']
        self._run_test('root', 'root', search_terms, "python3")

    def test_zz_cleaup_source_tree(self):
        '''Cleanup downloaded source'''
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)


class UfwLocales(UfwCommon):
    '''Test ufw locales'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = None
        self.builder = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)

        self.ufw_exe = "/usr/sbin/ufw"

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        self._tearDown()

        testlib.config_restore(self.ufw_exe)

    def test_locales(self):
        '''Test installed locales (this will take a while)'''
        build_dir = testlib.prepare_source('ufw', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        locales_dir = "/usr/share/ufw/messages"
        self.assertTrue(os.path.exists(locales_dir), "Could not find '%s'" % locales_dir)

        pythons = ['python']
        if self.lsb_release['Release'] >= 12.10:
            pythons.append("python3")

        exe = os.path.join(build_dir, "tests", "check-locales")
        if not os.path.exists(exe):
            exe = os.path.join(os.getcwd(), "ufw", "check-locales")
        self.assertTrue(os.path.exists(exe), "Could not find '%s'" % exe)

        locales = glob.glob("%s/*.mo" % locales_dir)
        locales.sort()
        print ""
        for python in pythons:
            print " %s:" % python

            lines = open(self.ufw_exe).readlines()
            lines[0] = '#!/usr/bin/%s\n' % python
            contents = "".join(lines)
            testlib.config_replace(self.ufw_exe, contents)
            for i in ['C'] + locales:
                loc = os.path.basename(i).split('.')[0]
                print "  %s:" % loc,
                sys.stdout.flush()

                rc, report = testlib.cmd([exe, '-f', '-i', '-d', locales_dir, '-l', loc])
                expected = 0
                result = 'Got exit code %d, expected %d\n' % (rc, expected)
                self.assertEquals(expected, rc, result + report)

                self.assertFalse("FAIL" in report, "Found 'FAIL' in report:\n%s" % report)
                print "ok"

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(UfwTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(UfwLocales))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(UfwTestsuite))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
