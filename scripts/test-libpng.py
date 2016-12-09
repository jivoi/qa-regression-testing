#!/usr/bin/python
#
#    test-libpng.py quality assurance test script for Xine
#    Copyright (C) 2009-2015 Canonical Ltd.
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

'''
  How to run in a clean virtual machine with sound enabled:
    1. apt-get -y install eog
    2. ./test-libpng.py download (as non-root)
    3. ./test-libpng.py -v       (as non-root)

  NOTES:
    When run with '--download', this file will download various files
    from ftp://ftp.simplesystems.org/pub/libpng/png/images/suite/ if they don't
    already exist. These files should not be added to the bzr branch for
    qa-regression-testing due to copyright.

    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test.

    The executables should be launched once and shutdown before running this
    script, so they can setup their config files
'''

# QRT-Depends: testlib_multimedia.py testlib_png data private/qrt/libpng.py
# QRT-Packages: unzip pngtools python-pexpect pngcrush

import unittest, os, sys
import tempfile
import testlib
import testlib_multimedia

topdir = os.path.join(os.getcwd(), "testlib_png")
topurl = "ftp://ftp.simplesystems.org/pub/libpng/png/images/suite/"
archive = "PngSuite.tar.gz"

use_x = False
use_private = True
try:
    from private.qrt.libpng import TestPNGPrivate
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class TestPNG(testlib_multimedia.MultimediaCommon):
    '''Test various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_multimedia.MultimediaCommon._setUp(self)
        self.exes = ['pnginfo', 'pngchunks']
        if use_x:
            self.exes.append('eog')

        self.files = []
        self.badfiles = []
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libpng-")

        do_download()

        print(["tar", "-C", topdir, "-xf", archive])
        (rc, report) = testlib.cmd(["tar", "-C", topdir, "-xf", topdir + '/' + archive])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for f in os.listdir(topdir):
            if not f.endswith('.png'):
                continue
            if f.startswith('x'):
                self.badfiles.append(f)
            else:
                self.files.append(f)

        self.files.sort()
        self.badfiles.sort()

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_png(self):
        '''Test PNG'''
        for exe in self.exes:
            files = []
            for f in self.files:
                files.append(f)

            search = ""
            expected = 0
            add_file_url = False
            if exe == "eog":
                add_file_url = True
            elif exe == "pnginfo": # These fail for some reason
                files.remove("ct1n0g04.png")
                files.remove("ctzn0g04.png")

                arch = testlib.get_arch()
                if arch == "x86_64" and self.lsb_release['Release'] == 14.04:
                    expected = 1
                if self.lsb_release['Release'] >= 15.04:
                    expected = None
                search = "Image Width:"
            elif exe == "pngchunks":
                search = "Chunk:"

            self._cmd([exe], files, "png", topdir, expected=expected, add_file_url=add_file_url, search=search)

    def test_badpng(self):
        '''Test Bad PNG files'''
        for exe in self.exes:
            if exe == "eog":
                self._cmd([exe], self.badfiles, "png", topdir)
                continue

            count = 1
            for bad in self.badfiles:
                f = os.path.join(topdir, bad)
                print "(%d of %d: Trying %s with %s)" % (count, len(self.badfiles), bad, exe)
                count += 1
                expected = 0
                search = ""
                if bad == "x00n0g01.png":
                    if exe == "pnginfo":
                        expected = 42
                        search = "Could not set PNG jump value"
                    elif exe == "pngchunks": # segfaults normally
                        continue
                elif (bad == "xcrn0g04.png" or bad == "xlfn0g04.png") and exe == "pngchunks":
                    expected = 1
                rc, report = testlib.cmd([exe, f])
                result = 'Got exit code %d, expected %d for \'%s %s\'\n' % (rc, expected, exe, f)
                self.assertEquals(expected, rc, result + report)
                if search != "":
                    self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def test_pngcrush(self):
        '''Test pngcrush'''
        files = []
        for f in self.files:
            files.append(f)
        # These fail for some reason
        files.remove("ct1n0g04.png")
        files.remove("ctzn0g04.png")

        count = 1
        for fn in files:
            f = os.path.join(topdir, fn)

            print "(%d of %d: Trying %s with pngcrush)" % (count, len(files), fn)
            count += 1

            rc, report = testlib.cmd(['pngcrush', '-d', '/tmp', '-v', '-n', f])
            expected = 0
            result = 'Got exit code %d, expected %d for \'%s\'\n' % (rc, expected, f)
            self.assertEquals(expected, rc, result + report)
            search = "FINISHED MAIN LOOP"
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))


def do_download():
    if not os.path.exists(topdir + '/' + archive):
        testlib_multimedia.download([archive], topurl, topdir)

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-d", "--download", dest="download", help="Download test data", action="store_true")
    parser.add_option("--with-x", dest="with_x", help="Add X display tests", action="store_true")
    (options, args) = parser.parse_args()

    if options.download:
        do_download()
        sys.exit(0)

    if options.with_x:
        use_x = True
    else:
        print "INFO: use '--with-x' to add X display tests"

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestPNG))
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestPNGPrivate))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)

    if not options.with_x:
        print "INFO: use '--with-x' to add X display tests"

    if not rc.wasSuccessful():
        sys.exit(1)

