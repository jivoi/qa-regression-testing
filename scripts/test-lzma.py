#!/usr/bin/python
#
#    test-lzma.py quality assurance test script for lzma
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Based on test-bzip2.py by Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: lzma file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/lzma.py testlib_compressor.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release lzma file  && ./test-lzma.py -v'
'''

import unittest, sys
import testlib_compressor
import os

recurse_directory = ""

try:
    from private.qrt.lzma import PrivateLzmaTest
except ImportError:
    class PrivateLzmaTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LzmaCommon(testlib_compressor.CompressorCommon):
    '''Test lzma.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_compressor.CompressorCommon._setUp(self)
        self.extension = ".lzma"

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_compressor.CompressorCommon._tearDown(self)

class LzmaTest(LzmaCommon, PrivateLzmaTest):
    def test_compress(self):
        '''Test lzma compression'''

        test_files = ( 'well-formed.gif',
                       'case_Contact.pdf',
                       'Edison_Phonograph_1.ogg',
                       'oo-presenting-ubuntu.odp' )

        for test_file in test_files:
            in_file = './data/' + test_file
            self._compress(["/usr/bin/lzma", "-c"], ["/usr/bin/unlzma", "-c"], ["/usr/bin/lzma", "-t"], self.extension, r"LZMA compressed data.*", in_file)

class LzmaTestLong(LzmaCommon):
    def test_compress_recursive(self):
        '''Test lzma compression on all files in a directory'''
        global recurse_directory
        path = "/usr"
        if recurse_directory != "":
            assert (os.path.isdir(recurse_directory))
            path = recurse_directory

        print "\n Scanning %s (this will take a while. Use '--quick' to skip):" % (path)
        num = self._rcompress(["/usr/bin/lzma", "-c"], ["/usr/bin/unlzma", "-c"], ["/usr/bin/lzma", "-t"], self.extension, r"LZMA compressed data.*", path)
        print "  --\n  Succesfully compressed/uncompressed %d files" % (num)

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-q", "--quick", dest="quick", help="Skip long running tests", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-d", "--directory", dest="directory", help="Specify directory to recursively compress", metavar="DIR")
    (options, args) = parser.parse_args()

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LzmaTest))

    if not options.quick:
        if options.directory:
            recurse_directory = options.directory
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LzmaTestLong))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
