#!/usr/bin/python
#
#    test-libgd2.py quality assurance test script for libgd2
#    Copyright (C) 2009-2016 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@videotron.ca>
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
# QRT-Packages: file libgd-tools
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: php5-cli php7.0-cli php5-gd php7.0-gd
# files and directories required for the test to run:
# QRT-Depends: private/qrt/libgd2.py libgd2 data

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file libgd-tools php5-cli php5-gd && ./test-libgd2.py -v'
'''

import unittest, sys
import testlib
import tempfile, os

use_private = True
try:
    from private.qrt.libgd2 import Libgd2PrivateTest
    from private.qrt.libgd2 import Phpgd2PrivateTest
except ImportError:
    class Libgd2PrivateTest(object):
        '''Empty class'''
    class Phpgd2PrivateTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class Libgd2Test(testlib.TestlibCase, Libgd2PrivateTest):
    '''Test libgd2.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libgd2-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _do_command(self, command, expected=0):
        '''Run a command and check the return code'''

        (rc, report) = testlib.cmd(command)
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_convert_gd(self):
        '''Test gd conversion utilities'''

        png_type = r'PNG image( data)?, 92 x 84, 8-bit/color RGB, non-interlaced'

        # Convert it to gd format
        outfilename = os.path.join(self.tempdir, "pngtogd.gd")
        self._do_command(["/usr/bin/pngtogd",
                          "./data/well-formed.png", outfilename])

        # Let's convert it back and check the mime-type
        refilename = os.path.join(self.tempdir, "gdtopng.png")
        self._do_command(["/usr/bin/gdtopng",
                          outfilename, refilename])
        self.assertFileType(refilename, png_type)

        # Let's try the gd file in the data directory
        datafilename = os.path.join(self.tempdir, "gdtopng-data.png")
        self._do_command(["/usr/bin/gdtopng",
                          "./data/well-formed.gd", datafilename])
        self.assertFileType(datafilename, png_type)

    def test_convert_gd2(self):
        '''Test gd2 conversion utilities'''

        png_type = r'PNG image( data)?, 92 x 84, 8-bit/color RGB, non-interlaced'

        # Convert it to gd2 format
        outfilename = os.path.join(self.tempdir, "pngtogd2.gd2")
        self._do_command(["/usr/bin/pngtogd2",
                          "./data/well-formed.png",
                          outfilename,
                          "5", "1"])

        # Let's convert it back and check the mime-type
        refilename = os.path.join(self.tempdir, "gd2topng.png")
        self._do_command(["/usr/bin/gd2topng",
                         outfilename, refilename])
        self.assertFileType(refilename, png_type)

        # Let's try the gd file in the data directory
        datafilename = os.path.join(self.tempdir, "gd2topng-data.png")
        self._do_command(["/usr/bin/gd2topng",
                          "./data/well-formed.gd2", datafilename])
        self.assertFileType(datafilename, png_type)

    def test_cve_2016_3074(self):
        '''Test CVE-2016-3074'''

        datafilename = os.path.join(self.tempdir, "gd2topng-data.png")
        self._do_command(["/usr/bin/gd2topng",
                          "libgd2/CVE-2016-3074/invalid_neg_size.gd2",
                          datafilename], expected=1)


class Phpgd2Test(testlib.TestlibCase, Phpgd2PrivateTest):
    '''Test libgd2.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libgd2-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_script(self, contents, expected=0, args=[]):
        '''Run a php script, expecting exit code 0'''

        if self.lsb_release['Release'] >= 16.04:
            php_bin = "/usr/bin/php7.0"
        else:
            php_bin = "/usr/bin/php5"

        handle, name = testlib.mkstemp_fill('<?php\n'+contents+'\n?>\n', dir=self.tempdir)
        self.assertShellExitEquals(expected, [php_bin] + args, stdin = handle)
        os.unlink(name)

    def test_imageCreateTrueColor(self):
        '''Test php imageCreateTrueColor'''

        self._run_script('''
header ("Content-type: image/png");
$im = imageCreateTrueColor(300,300) or die("Cannot Initialize new GD image stream");

$text_color = imagecolorallocate($im, 233, 14, 91);
imagestring($im, 1, 5, 5,  "A Simple Text String", $text_color);
imagepng($im);
imagedestroy($im);
exit(0);
''')

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Libgd2Test))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Phpgd2Test))

    # Pull in private tests
    #if use_private:
    #    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Libgd2PrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
