#!/usr/bin/python
#
#    test-poppler.py quality assurance test script for poppler
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file poppler-utils  && ./test-poppler.py -v'
'''

# QRT-Depends: data private/qrt/poppler.py
# QRT-Packages: poppler-utils

import unittest, sys, tempfile, os
import testlib

use_private = True
try:
    from private.qrt.poppler import PopplerPrivateTests
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class PopplerTest(testlib.TestlibCase):
    '''Test poppler.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="poppler-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _check_mime_type(self, filename, mimetype):
        '''Checks the mime type of the file specified'''

        (rc, report) = testlib.cmd(["/usr/bin/file", "-b", os.path.join(self.tempdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = 'Mime type from file: %s, expected: %s\n' % (report, mimetype)
        self.assertEquals(report.rstrip(), mimetype, result)

    def _pdfinfo_check_header(self, report, header, value):
        '''Checks if the header contains the required value'''

        header_contents = ''

        for line in report.splitlines():
            if line.split(':', 1)[0] == header:
                header_contents = line.split(':', 1)[1].lstrip()

        result = "Header '%s' contained: '%s', expected: '%s'\n" % (header, header_contents, value)
        self.assertEquals(header_contents, value, result)


    def test_pdfinfo(self):
        '''Test the pdfinfo utility'''

        samples = ( ('data/case_Contact.pdf',                # File name
                     'Writer',                                  # Creator
                     '1',                                       # Pages
                     '595 x 842 pts (A4)',                      # Page size
                     '1.4'),                                    # PDF version

                    ('data/case_howard_county_library.pdf',  # File name
                     'Adobe InDesign CS3 (5.0)',                # Creator
                     '3',                                       # Pages
                     '595.276 x 841.89 pts (A4)',               # Page size
                     '1.4'),                                    # PDF version

                    ('data/case_KRUU.pdf',                   # File name
                     'Writer',                                  # Creator
                     '1',                                       # Pages
                     '595 x 842 pts (A4)',                      # Page size
                     '1.4'),                                    # PDF version

                    ('data/case_ubuntu_johnshopkins_v2.pdf', # File name
                     'Adobe InDesign CS (3.0.1)',               # Creator
                     '2',                                       # Pages
                     '595.276 x 841.89 pts (A4)',               # Page size
                     '1.5') )                                   # PDF version

        for filename, creator, pages, pagesize, pdfversion in samples:
            (rc, report) = testlib.cmd(["/usr/bin/pdfinfo", filename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._pdfinfo_check_header(report, 'Creator', creator)
            self._pdfinfo_check_header(report, 'Pages', pages)
            self._pdfinfo_check_header(report, 'Page size', pagesize)
            self._pdfinfo_check_header(report, 'PDF version', pdfversion)

    def test_pdftops(self):
        '''Test pdftops utility'''

        if self.lsb_release['Release'] <= 8.04:
            ps_filetype = 'PostScript document text conforming at level 3.0'
        else:
            ps_filetype = 'PostScript document text conforming DSC level 3.0, Level 2'

        conversions = ( 'case_Contact.pdf',
                        'case_howard_county_library.pdf',
                        'case_KRUU.pdf',
                        'case_OaklandUniversity.pdf',
                        'case_oxford_archaeology.pdf',
                        'case_Skegness.pdf',
                        'case_ubuntu_johnshopkins_v2.pdf',
                        'case_ubuntu_locatrix_v1.pdf',
                        'case_Wellcome.pdf' )

        for filename in conversions:

            outfilename = filename.replace('.pdf', '.ps')

            (rc, report) = testlib.cmd(["/usr/bin/pdftops",
                                        os.path.join("data/", filename),
                                        os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid PostScript file
            self._check_mime_type(outfilename, ps_filetype)

if __name__ == '__main__':
    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PopplerTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PopplerPrivateTests))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
