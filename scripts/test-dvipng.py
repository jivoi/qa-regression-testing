#!/usr/bin/python
#
#    test-dvipng.py quality assurance test script for dvipng
#    Copyright (C) 2010-2011 Canonical Ltd.
#    Authors:
#      Marc Deslauriers <marc.deslauriers@canonical.com>
#      Kees Cook <kees.cook@canonical.com>
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
# QRT-Packages: dvipng file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/dvipng.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file dvipng && ./test-dvipng.py -v'
'''


import unittest, sys, os, tempfile
import testlib

try:
    from private.qrt.dvipng import PrivateDvipngTest
except ImportError:
    class PrivateDvipngTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class DvipngTest(testlib.TestlibCase, PrivateDvipngTest):
    '''Test dvipng.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="dvipng-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_convert(self):
        '''Test dvigif and dvipng utilities'''

        conversions = ( ('gif', 'GIF image data, version 87a, 594 x 876'),
                        ('png', r'PNG image( data)?, 594 x 876, 8-bit/color RGB, non-interlaced') )


        for outfiletype, outmimetype in conversions:
            outfilename = os.path.join(self.tempdir, "test-" + outfiletype + "." + outfiletype)

            (rc, report) = testlib.cmd(["/usr/bin/dvi" + outfiletype,
                                        "-o", outfilename,
                                        "./data/test.dvi"])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid image
            self.assertFileType(outfilename, outmimetype)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
