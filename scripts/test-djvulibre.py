#!/usr/bin/python
#
#    test-djvulibre.py quality assurance test script for djvulibre
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
# QRT-Packages: djvulibre-bin file
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-<script>.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-<script>.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-<script>.tar.gz
    # cd /tmp/qrt-test-<script> ; ./install-packages ./test-<script>.py
    # ./test-<script>.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import os
import subprocess
import sys
import unittest
import tempfile
import testlib

try:
    from private.qrt.djvulibre import PrivateDjvulibreTest
except ImportError:
    class PrivateDjvulibreTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class DjvulibreTest(testlib.TestlibCase, PrivateDjvulibreTest):
    '''Test djvulibre.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="djvulibre-")

        self.samples = ( 'cups_testprint.djvu',
                         'djvu2spec.djvu',
                         'djvu3spec.djvu',
                         'djvulibre-book-en.djvu',
                         'djvulibre-book-ru.djvu',
                         'lizard2002.djvu',
                         'lizard2007.djvu' )

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)


    def test_ddjvu(self):
        '''Test ddjvu utility'''

        for infile in self.samples:
            outfilename = os.path.join(self.tempdir, infile.replace('djvu', 'pdf'))

            (rc, report) = testlib.cmd(["/usr/bin/ddjvu",
                                        "-format=pdf",
                                        "./data/" + infile,
                                        outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(outfilename, r'PDF document, version 1.[12]')

    def test_djvups(self):
        '''Test djvups utility'''

        for infile in self.samples:
            outfilename = os.path.join(self.tempdir, infile.replace('djvu', 'ps'))

            (rc, report) = testlib.cmd(["/usr/bin/djvups",
                                        "./data/" + infile,
                                        outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(outfilename,
                                'PostScript document text conforming DSC level 3.0, Level 2')

    def test_djvudump(self):
        '''Test djvudump utility'''

        dump_samples = ( ('cups_testprint.djvu',
                          'DjVu 2550x3300, v24, 300 dpi, gamma=2.2',
                          'shared_anno.iff' ),

                         ('djvu2spec.djvu',
                          'DjVu 2550x3300, v21, 300 dpi, gamma=2.2',
                          'p0039.djvu' ),

                         ('djvu3spec.djvu',
                          'DjVu 2550x3300, v21, 300 dpi, gamma=2.2',
                          'p0071.djvu' ),

                         ('djvulibre-book-en.djvu',
                          'DjVu 3400x4400, v21, 400 dpi, gamma=2.2',
                          'p0057.djvu' ),

                         ('djvulibre-book-ru.djvu',
                          'DjVu 3307x4678, v24, 400 dpi, gamma=2.2',
                          'nb20032.djvu' ),

                         ('lizard2002.djvu',
                          'DjVu 2539x3295, v22, 300 dpi, gamma=2.2',
                          'p0002.djvu' ),

                         ('lizard2007.djvu',
                          'DjVu 2550x3300, v25, 300 dpi, gamma=2.2',
                          'scandjvutmp32_0001.djvu' ) )


        for infile, info, last_page in dump_samples:

            (rc, report) = testlib.cmd(["/usr/bin/djvudump",
                                        "./data/" + infile])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = "Could not find '%s' in '%s'\n" % (info, report)
            self.assertTrue(info in report, result)
            result = "Could not find '%s' in '%s'\n" % (last_page, report)
            self.assertTrue(last_page in report, result)

    def test_djvutxt(self):
        '''Test djvutxt utility'''

        dump_samples = ( ('cups_testprint.djvu',
                          'Printed Using CUPS v1.3.x' ),

                         ('djvu2spec.djvu',
                          'Version of 1999 04 29' ),

                         ('djvu3spec.djvu',
                          'Document Date: November 2005' ),

                         ('djvulibre-book-en.djvu',
                          'is the relatively high cost' ),

                         ('djvulibre-book-ru.djvu',
                          'v. 2.5' ),

                         ('lizard2002.djvu',
                          'July 19, 2002' ),

                         ('lizard2007.djvu',
                          'February 28, 2007' ) )


        for infile, search in dump_samples:

            (rc, report) = testlib.cmd(["/usr/bin/djvutxt",
                                        "--page=1",
                                        "./data/" + infile])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = "Could not find '%s' in '%s'\n" % (search, report)
            self.assertTrue(search in report, result)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
