#!/usr/bin/python
#
#    test-t1lib.py quality assurance test script for t1lib
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
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
  This test script needs to be run in a VM.

  How to run:
    $ sudo apt-get -y install lsb-release
    $ sudo ./test-t1lib.py -v

'''

# QRT-Depends: testlib_data.py private/qrt/t1lib.py
# QRT-Packages: libt1-5 t1lib-bin php5-cli php5-gd

import unittest, sys, os
import testlib, testlib_data

do_interactive = False

use_private = True
try:
    from private.qrt.t1lib import T1libPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class T1libTest(testlib_data.DataCommon):
    '''Test t1lib'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.tmpdir = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_xglyph(self):
        '''Test libt1 with xglyph'''
        global do_interactive
        if not do_interactive:
            return self._skipped("please specify --interactive for xglyph tests")
        print "\nNOTE: Press 'String', 'Char', etc., to test"
        print "NOTE: Press 'Exit Program' when done. xglyph will return an error if you press 'X' to exit"
        self._cmd(['xglyph'], "pfb", url=False)

    def test_type1afm(self):
        '''Test libt1 with type1afm'''
        self.tmpdir = self.cp_data_to_tmpdir('pfb')
        self._cmd(['type1afm'], "pfb", url=False, dir=self.tmpdir)

    def test_php5_gd(self):
        '''Test php5-gd'''
        self.tmpdir = self.cp_data_to_tmpdir('pfb')

        for f in self.files:
            if not f.endswith('.pfb'):
                continue
            fontpath = os.path.join(self.tmpdir, f)
            php_script = fontpath + ".php"
            pngpath = fontpath + ".png"
            stderr = fontpath + ".stderr"

            contents = '''<?php
// Create a new image instance
$im = imagecreatetruecolor(200, 200);
$black = imagecolorallocate($im, 0, 0, 0);
$white = imagecolorallocate($im, 255, 255, 255);

// Make the background white
imagefilledrectangle($im, 0, 0, 199, 199, $white);

// Load the gd font and write 'String'
$font = imagepsloadfont('%s');

// Write the font to the image
imagepstext($im, 'String', $font, 36, $black, $white, 50, 50);

// output to browser
header("Content-type: image/png");
imagepng($im);
imagedestroy($im);
?>''' % (fontpath)

            testlib.create_fill(php_script, contents)

            handle = file(pngpath, 'w')
            handle_stderr = file(stderr, 'w')
            rc, report = testlib.cmd(['php5', php_script], stdout=handle, stderr=handle_stderr)
            handle.close()
            handle_stderr.close()

            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd(['file', pngpath])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue("PNG image" in report, "Could not find 'PNG image' in report:\n" + report)


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--interactive':
        do_interactive = True

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(T1libTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(T1libPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
