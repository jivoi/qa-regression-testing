#!/usr/bin/python
#
#    test-cups-filters.py quality assurance test script for cups-filters
#    Copyright (C) 2014-2015 Canonical Ltd.
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
# QRT-Depends: data private/qrt/cupsfilters.py
# QRT-Packages: cups-filters
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-cups-filters.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-cups-filters.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-cups-filters.tar.gz
    # cd /tmp/qrt-test-cups-filters ; ./install-packages ./test-cups-filters.py
    # ./test-cups-filters.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-cups-filters.py

'''


import os
import subprocess
import sys
import tempfile
import time
import unittest
import testlib

try:
    from private.qrt.cupsfilters import PrivateCupsFiltersTest
except ImportError:
    class PrivateCupsFiltersTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class CupsFiltersTest(testlib.TestlibCase, PrivateCupsFiltersTest):
    '''Test cups-filters.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')

        self.input = os.path.join(self.tmpdir, "filter.in")
        self.output = os.path.join(self.tmpdir, "output.ps")
        self.filter_path = "/usr/lib/cups/filter"

    def tearDown(self):
        '''Clean up after each test_* function'''
        testlib.recursive_rm(self.tmpdir)

    def _filter_test(self, filter, input=None, output=None,
                     stderr=subprocess.PIPE, expected=0,
                     search = "PostScript"):
        '''Test the filter'''
        if not input:
            input = self.input

        if not os.path.exists(input):
            raise IOError, 'Could not open "%s" (not found)' % input

        if not output:
            output = self.output

        try:
            fh = open(output, 'w')
        except:
            raise

        subprocess.Popen([filter, '1', str(os.getuid()), "title_" + filter, \
                          "1", "-", input], stdout=fh.fileno(), \
                          stderr=stderr)
        fh.flush()
        fh.close()
        time.sleep(3)

        rc, report = testlib.cmd(['file', output])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if expected == 0:
            self.assertTrue(search in report, "Could not find '%s' in %s" % (search, report))

        os.unlink(output)

    def test_texttops(self):
        '''Test texttops'''
        text = '''some random
text
'''
        try:
            fh = open(self.input, 'w')
            fh.write(text)
            fh.close()
        except:
            raise

        self._filter_test(os.path.join(self.filter_path, "texttops"))

    def test_texttopdf(self):
        '''Test texttopdf'''
        text = '''some random
text
'''
        try:
            fh = open(self.input, 'w')
            fh.write(text)
            fh.close()
        except:
            raise

        self._filter_test(os.path.join(self.filter_path, "texttopdf"),
                          search = "PDF document")

    def test_pdftops(self):
        '''Test pdftops'''

        self._filter_test(os.path.join(self.filter_path, "pdftops"),
                          input='./data/case_ubuntu_locatrix_v1.pdf')

    def test_pdftopdf(self):
        '''Test pdftopdf'''

        self._filter_test(os.path.join(self.filter_path, "pdftopdf"),
                          input='./data/case_ubuntu_locatrix_v1.pdf',
                          search = "PDF document")

    def test_pstopdf(self):
        '''Test pstopdf'''

        self._filter_test(os.path.join(self.filter_path, "pstopdf"),
                          input='./data/cups_testprint.ps',
                          search = "PDF document")

    def test_imagetopdf(self):
        '''Test imagetopdf'''

        self._filter_test(os.path.join(self.filter_path, "imagetopdf"),
                          input='./data/well-formed.jpg',
                          search = "PDF document")

    def test_imagetops(self):
        '''Test imagetops'''

        self._filter_test(os.path.join(self.filter_path, "imagetops"),
                          input='./data/well-formed.jpg')

    def test_foomatic_rip(self):
        '''Test foomatic-rip'''

        if self.lsb_release['Release'] == 12.04:
            ppd = "/usr/share/ppd/cupsfilters/Generic-PDF_Printer-PDF.ppd"
        else:
            ppd = "/usr/share/ppd/cupsfilters/pxlcolor.ppd"

        (rc, report) = testlib.cmd(["/usr/lib/cups/filter/foomatic-rip",
                                    "--ppd", ppd,
                                    "./data/cups_testprint.ps"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "PostScript test page"
        result = 'Did not find "%s" in output "%s"!\n' % (search, report)
        self.assertTrue(search in report, result)


    # Need to figure out how to test these, disabled for now
    def disabled_test_imagetoraster(self):
        '''Test imagetoraster'''

        self._filter_test(os.path.join(self.filter_path, "imagetoraster"),
                          input='./data/well-formed.jpg',
                          search = "aaa")

    def disabled_test_pdftoijs(self):
        '''Test pdftoijs'''

        self._filter_test(os.path.join(self.filter_path, "pdftoijs"),
                          input='./data/case_ubuntu_locatrix_v1.pdf',
                          search = "bbb")

    def disabled_test_pdftoopvp(self):
        '''Test pdftoopvp'''

        self._filter_test(os.path.join(self.filter_path, "pdftoopvp"),
                          input='./data/case_ubuntu_locatrix_v1.pdf',
                          search = "ccc")

if __name__ == '__main__':
    print >>sys.stderr, "Please also run the test-cups.py browsing tests"
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
