#!/usr/bin/python
#
#    test-lzop.py quality assurance test script for lzop
#    Copyright (C) 2014 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: lzop file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data testlib_compressor.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''

import unittest, sys
import testlib_compressor
import os

recurse_directory = ""

try:
    from private.qrt.lzop import PrivateLzopTest
except ImportError:
    class PrivateLzopTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LzopCommon(testlib_compressor.CompressorCommon):
    '''Test lzop.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_compressor.CompressorCommon._setUp(self)
        self.extension = ".lzo"

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_compressor.CompressorCommon._tearDown(self)

class LzopTest(LzopCommon, PrivateLzopTest):
    def test_compress(self):
        '''Test lzop compression'''

        test_files = ( 'well-formed.gif',
                       'case_Contact.pdf',
                       'Edison_Phonograph_1.ogg',
                       'oo-presenting-ubuntu.odp' )

        for test_file in test_files:
            in_file = './data/' + test_file
            self._compress(["/usr/bin/lzop", "-c"],
                           ["/usr/bin/lzop", "-d", "-c"],
                           ["/usr/bin/lzop", "-t"],
                           self.extension,
                           r"lzop compressed data.*",
                           in_file)

class LzopTestLong(LzopCommon):
    def test_compress_recursive(self):
        '''Test lzop compression on all files in a directory'''
        global recurse_directory
        path = "/usr"
        if recurse_directory != "":
            assert (os.path.isdir(recurse_directory))
            path = recurse_directory

        print "\n Scanning %s (this will take a while. Use '--quick' to skip):" % (path)
        num = self._rcompress(["/usr/bin/lzop", "-c"],
                              ["/usr/bin/lzop", "-d", "-c"],
                              ["/usr/bin/lzop", "-t"],
                              self.extension,
                              r"lzop compressed data.*",
                              path)

        print "  --\n  Succesfully compressed/uncompressed %d files" % (num)

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-q", "--quick", dest="quick", help="Skip long running tests", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-d", "--directory", dest="directory", help="Specify directory to recursively compress", metavar="DIR")
    (options, args) = parser.parse_args()

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LzopTest))

    if not options.quick:
        if options.directory:
            recurse_directory = options.directory
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LzopTestLong))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
