#!/usr/bin/python
#
#    test-patch.py quality assurance test script for patch
#    Copyright (C) 2015 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
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
# QRT-Packages: patch
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/patch.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-patch.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-patch.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-patch.tar.gz
    # cd /tmp/qrt-test-patch ; ./install-packages ./test-patch.py
    # ./test-patch.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import os, subprocess, sys, tempfile
import unittest
import testlib

try:
    from private.qrt.Pkg import PrivatePatchTest
except ImportError:
    class PrivatePatchTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class PatchTest(testlib.TestlibCase, PrivatePatchTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='test-patch-', dir='/tmp')
        self.baddir = os.path.join(self.tmpdir, "bad");
        self.workdir = os.path.join(self.tmpdir, "work");
        os.mkdir(self.baddir)
        os.mkdir(self.workdir)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_cve_2010_4651(self):
        '''Test CVE-2014-9447'''
        patch = os.path.join(self.tmpdir, "test.patch")
        target = "foo"
        bad_abs = os.path.join(self.baddir, target);
        bad_rel = os.path.relpath(bad_abs, self.workdir)

        contents = '''
--- /dev/null
+++ %s
@@ -0,0 +1 @@
+ 
''' % (bad_rel)
        testlib.create_fill(patch, contents)

        rc, report = testlib.cmd(['patch', '-p0', '-i', patch, '-d', self.workdir])
        self.assertFalse(os.path.exists(bad_abs))
        self.assertTrue('Ignoring potentially dangerous file name %s' % (bad_rel) in report)
        self.assertTrue(rc == 1, report)

    def test_cve_2014_9637(self):
        '''Test CVE-2014-9637'''
        patch = os.path.join(self.tmpdir, "test.patch")
        contents = '''
--- /dev/null
+++ foo
@@ -0,655555555555555 +1 @@
+ 
'''
        testlib.create_fill(patch, contents)

        rc, report = testlib.cmd(['patch', '-p0', '-i', patch, '-d', self.workdir])
        self.assertTrue(rc == 2, report)
        self.assertTrue('patch: **** out of memory' in report)

    def test_cve_2015_1395(self):
        '''Test CVE-2015-1395'''
        if self.lsb_release['Release'] < 14.04:
            return self._skipped("git style only present in Trusty and later")
        patch = os.path.join(self.tmpdir, "test.patch")
        target = "foo"
        bad_abs = os.path.join(self.baddir, target);
        bad_rel = os.path.relpath(bad_abs, self.workdir)

        contents = '''
diff --git a/foo b/foo
new file mode 100644
--- /dev/null
+++ b/%s
@@ -0,0 +1 @@
+foo
diff --git a/foo a/%s
rename from x
rename to x
''' % (bad_abs, bad_rel)
        testlib.create_fill(patch, contents)

        rc, report = testlib.cmd(['patch', '-p1', '-i', patch, '-d', self.workdir])
        self.assertFalse(os.path.exists(bad_abs))
        self.assertTrue(os.path.exists(os.path.join(self.workdir, target)))
        self.assertTrue(rc == 1, report)

    def test_cve_2015_1396_regression(self):
        '''Test that the regression reported against the original CVE-2015-1396 fix is not present'''
        '''https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=777122'''
        patch = os.path.join(self.tmpdir, "test.patch")
        dir = os.path.join(self.workdir, "dir")
        link = os.path.join(self.workdir, "link")
        os.mkdir(dir)
        os.symlink("dir", link)
        testlib.create_fill(os.path.join(dir, "file"), "hello\n")

        contents = '''
--- a/link/file 2015-06-17 23:29:21.723141442 -0500
+++ b/link/file 2015-06-17 23:29:26.235116098 -0500
@@ -1 +1 @@
-hello
+world
'''
        testlib.create_fill(patch, contents)

        rc, report = testlib.cmd(['patch', '-p1', '-i', patch, '-d', self.workdir])
        self.assertTrue(rc == 0, report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PatchTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
