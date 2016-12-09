#!/usr/bin/python
#
#    test-bzip2.py quality assurance test script for bzip2
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
# QRT-Packages: bzip2 file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/bzip2.py testlib_compressor.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release bzip2 file && ./test-bzip2.py -v'
'''

import unittest, sys
import testlib
import testlib_compressor
import tempfile, os, shutil

recurse_directory = ""

try:
    from private.qrt.bzip2 import PrivateBzip2Test
except ImportError:
    class PrivateBzip2Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class Bzip2Common(testlib_compressor.CompressorCommon):
    '''Test bzip2'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_compressor.CompressorCommon._setUp(self)
        self.extension = ".bz2"

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib_compressor.CompressorCommon._tearDown(self)

class Bzip2Test(Bzip2Common, PrivateBzip2Test):
    def test_compress(self):
        '''Test bzip2 compression'''

        test_files = ( 'well-formed.gif',
                       'case_Contact.pdf',
                       'Edison_Phonograph_1.ogg',
                       'oo-presenting-ubuntu.odp' )

        for test_file in test_files:
            in_file = './data/' + test_file
            self._compress(["/bin/bzip2", "-c"], ["/bin/bunzip2", "-c"], ["/bin/bzip2", "-t"], self.extension, r"bzip2 compressed data.*", in_file)

    def test_libbz2(self):
        '''Test libbz2 (via python)'''
        import bz2
        msg = "Test message for libbz2"
        c = bz2.compress(msg)
        u = bz2.decompress(c)
        self.assertTrue(msg == u, "'%s' does not equal '%s'" % (msg, u))

        # incremental
        compressor = bz2.BZ2Compressor()
        data = ""
        for w in msg.split():
            data += compressor.compress(w + " ")
        data += compressor.flush()
        search = msg + " "
        u = bz2.decompress(data)
        self.assertTrue(search == u, "'%s' does not equal '%s'" % (search, u))

    def test_cve_2011_4089(self):
        '''Test CVE-2011-4089 (bzexe)'''
        # Create a tmp dir to act as the bzexe link target and to store the
        # bzip'ed binary. We'll zip up /bin/true for this test.
        tmpdir = tempfile.mkdtemp(prefix='true', dir='/tmp')

        # Reuse the name of the temp dir for the name of the bzip'ed true binary
        true_path = os.path.join(tmpdir, os.path.basename(tmpdir))
        shutil.copyfile('/bin/true', true_path)
        testlib.cmd(['bzexe', true_path])

        # If we gain a file in tmpdir, it means that the uncompressing script
        # treated it like a regular file, leaving the possibility of a race
        files_before = len(os.listdir(tmpdir))
        testlib.cmd(['sh', true_path])
        files_after = len(os.listdir(tmpdir))
        shutil.rmtree(tmpdir)
        self.assertTrue(files_before == files_after)

class Bzip2TestLong(Bzip2Common):
    def test_compress(self):
        '''Test bzip2 compression on all files in a directory'''
        global recurse_directory
        path = "/usr"
        if recurse_directory != "":
            assert (os.path.isdir(recurse_directory))
            path = recurse_directory

        print "\n Scanning %s (this will take a while. Use '--quick' to skip):" % (path)
        num = self._rcompress(["/bin/bzip2", "-c"], ["/bin/bunzip2", "-c"], ["/bin/bzip2", "-t"], self.extension, r"bzip2 compressed data.*", path)
        print "  --\n  Succesfully compressed/uncompressed %d files" % (num)


if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-q", "--quick", dest="quick", help="Skip long running tests", action="store_true")
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-d", "--directory", dest="directory", help="Specify directory to recursively compress", metavar="DIR")
    (options, args) = parser.parse_args()

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Bzip2Test))
    if not options.quick:
        if options.directory:
            recurse_directory = options.directory
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Bzip2TestLong))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
