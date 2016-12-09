#!/usr/bin/python
#
#    test-libraw.py quality assurance test script for libraw
#    Copyright (C) 2013 Canonical Ltd.
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
# QRT-Packages: libraw-bin libtiff-tools netpbm
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data
# privilege required for the test to run (remove line if running as user is okay):

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-libraw.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-libraw.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-libraw.tar.gz
    # cd /tmp/qrt-test-libraw ; ./install-packages ./test-libraw.py
    # ./test-libraw.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-libraw.py

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-libraw.py -v'
'''


import unittest, sys, os, tempfile, shutil, re
import testlib

try:
    from private.qrt.libraw import PrivateLibrawTest
except ImportError:
    class PrivateLibrawTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibrawTest(testlib.TestlibCase, PrivateLibrawTest):
    '''Test libraw.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libraw-")
        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _tiffinfo_check(self, filename):
        '''Checks if the file specified can be parsed with tiffinfo'''

        command = ["/usr/bin/tiffinfo", filename]

        (rc, report) = testlib.cmd(command)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        checks = ( 'TIFF Directory at', 'Image Width', 'Compression Scheme' )
        for check in checks:
            result = "Couldn't find '%s' in report: %s\n" % (check, report)
            self.assertTrue(check in report, result)


    def _pnmfile_check(self, filename, expected_out):
        '''Checks if the file specified can be parsed with pnmfile'''

        (rc, report, out) = self._testlib_shell_cmd(["/usr/bin/pnmfile", filename])
        out = out.split(':')[1].strip()
        expected = 0
        result = 'Got exit code %d, expected %d:\n%s\n' % (rc, expected, report)
        self.assertEquals(expected, rc, result)

        expected_out = '^%s$' % (expected_out)
        result = 'File info for %s reported by pnmfile: [%s], expected regex: [%s]\n' % (filename, out, expected_out)
        self.assertNotEquals(None, re.search(expected_out, out), result)


    def test_4channels(self):
        '''Test 4channels utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)

        (rc, report) = testlib.cmd(["/usr/lib/libraw/4channels",
                                    os.path.join(self.tempdir, "cat.cr2")])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if mime types of extracted files make sense
        expected_mime = 'TIFF image data, little-endian'

        for file_ext in ('R', 'G', 'B', 'G2'):
            filename = os.path.join(self.tempdir, "cat.cr2.%s.tiff" % file_ext)
            self.assertFileType(filename, expected_mime)
            # Let's see if it generated a valid tiff image
            self._tiffinfo_check(filename)


    def test_dcraw_emu(self):
        '''Test dcraw_emu utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)
        filename = os.path.join(self.tempdir, "cat.cr2")
        out_filename = filename + '.ppm'

        (rc, report) = testlib.cmd(["/usr/lib/libraw/dcraw_emu", filename])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if the extracted file make sense
        self.assertFileType(out_filename, 'Netpbm PPM "rawbits" image data')
        self._pnmfile_check(out_filename, 'PPM raw, 3684 by 2760  maxval 255')

    def test_dcraw_half(self):
        '''Test dcraw_half utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)
        filename = os.path.join(self.tempdir, "cat.cr2")
        out_filename = filename + '.ppm'

        (rc, report) = testlib.cmd(["/usr/lib/libraw/dcraw_half", filename])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if the extracted file make sense
        self.assertFileType(out_filename, 'Netpbm PPM "rawbits" image data')
        self._pnmfile_check(out_filename, 'PPM raw, 1842 by 1380  maxval 255')

    def test_unprocessed_raw(self):
        '''Test unprocessed_raw utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)
        filename = os.path.join(self.tempdir, "cat.cr2")
        out_filename = filename + '.pgm'

        (rc, report) = testlib.cmd(["/usr/lib/libraw/unprocessed_raw", filename])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if the extracted file make sense
        self.assertFileType(out_filename, 'Netpbm PGM "rawbits" image data')
        self._pnmfile_check(out_filename, 'PGM raw, 3744 by 2784  maxval 65535')

    def test_simple_dcraw(self):
        '''Test simple_dcraw utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)
        filename = os.path.join(self.tempdir, "cat.cr2")
        out_filename = filename + '.ppm'

        (rc, report) = testlib.cmd(["/usr/lib/libraw/simple_dcraw", filename])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if the extracted file make sense
        self.assertFileType(out_filename, 'Netpbm PPM "rawbits" image data')
        self._pnmfile_check(out_filename, 'PPM raw, 3684 by 2760  maxval 255')

    def test_half_mt(self):
        '''Test half_mt utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)
        filename = os.path.join(self.tempdir, "cat.cr2")
        out_filename = filename + '.ppm'

        (rc, report) = testlib.cmd(["/usr/lib/libraw/half_mt", filename])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if the extracted file make sense
        self.assertFileType(out_filename, 'Netpbm PPM "rawbits" image data')
        self._pnmfile_check(out_filename, 'PPM raw, 1842 by 1380  maxval 255')

    def test_mem_image(self):
        '''Test mem_image utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)
        filename = os.path.join(self.tempdir, "cat.cr2")
        out_filename = filename + '.ppm'

        (rc, report) = testlib.cmd(["/usr/lib/libraw/mem_image", filename])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if the extracted file make sense
        self.assertFileType(out_filename, 'Netpbm PPM "rawbits" image data')
        self._pnmfile_check(out_filename, 'PPM raw, 3684 by 2760  maxval 255')

    def test_multirender_test(self):
        '''Test multirender_test utility'''

        # Copy test file to tmpdir, as utility extracts into the
        # same directory as the original file
        shutil.copy("./data/cat.cr2", self.tempdir)

        (rc, report) = testlib.cmd(["/usr/lib/libraw/multirender_test",
                                    os.path.join(self.tempdir, "cat.cr2")])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Now check to see if mime types of extracted files make sense
        for file_num in range(1,9):
            out_filename = os.path.join(self.tempdir, "cat.cr2.%s.ppm" % file_num)
            self.assertFileType(out_filename, 'Netpbm PPM "rawbits" image data')
            expected_info = 'PPM raw, 3684 by 2760  maxval 255'
            if file_num in (2, 3, 4, 5, 6, 7):
                expected_info = 'PPM raw, 1842 by 1380  maxval 255'
            self._pnmfile_check(out_filename, expected_info)

    def test_postprocessing_benchmark(self):
        '''Test postprocessing_benchmark utility'''

        (rc, report) = testlib.cmd(["/usr/lib/libraw/postprocessing_benchmark",
                                    "./data/cat.cr2"])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_string = 'frames/sec'
        result = "Could not find %s in '%s'\n" % (expected_string, report)
        self.assertTrue(expected_string in report, result)

    def test_raw_identify(self):
        '''Test raw-identify utility'''

        (rc, report) = testlib.cmd(["/usr/lib/libraw/raw-identify",
                                    "./data/cat.cr2"])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_string = 'is a Canon PowerShot S95 image.'
        result = "Could not find %s in '%s'\n" % (expected_string, report)
        self.assertTrue(expected_string in report, result)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
