#!/usr/bin/python
#
#    test-ghostscript.py quality assurance test script
#    Copyright (C) 2008-2011 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
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
  How to run:
    $ sudo apt-get install ghostscript cups file lsb-release
    $ ./test-ghostscript.py -v'

  TODO:
    - more thorough testing of gs (currently only write to nullpage)
    - test other utilities besides ps2*
'''

# QRT-Depends: data private/qrt/ghostscript.py
# QRT-Packages: ghostscript file

import unittest, os, tempfile
import sys
import testlib

use_private = True
try:
    from private.qrt.ghostscript import GhostscriptPrivateTests
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class GhostscriptTest(testlib.TestlibCase):
    '''Test ghostscript/gs-esp/gs-gpl functionality'''

    def setUp(self):
        '''setUp'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="ghostscript-")
        self.ps = "./data/cups_testprint.ps"

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

    def test_ps2utils(self):
        '''Test ps2* utilities'''

        utils = ['ps2ascii', 'ps2epsi', 'ps2pdf', 'ps2pdf12', 'ps2pdf13', \
                  'ps2pdf14', 'ps2pdfwr', 'ps2ps', 'ps2ps2', 'ps2txt']
        if self.lsb_release['Release'] == 6.06:
            # These don't exist on Dapper
            utils.remove("ps2txt")
            utils.remove("ps2ps2")

        errors = 0
        errstr = ""
        for util in utils:
            self.out = os.path.join(self.tempdir, "out." + util[3:])
            rc, report = testlib.cmd([util, self.ps, self.out])
            expected = 0
            if rc != expected:
                result = '\'%s\' returned exit code %d, expected %d\n' % \
                         (util, rc, expected)
                errstr = errstr + result + report
                errors += 1

        self.assertEquals(errors, 0, errstr)

    def test_pdf2ps(self):
        '''Test pdf2ps utility'''

        conversions = ( 'case_Contact.pdf',
                        'case_howard_county_library.pdf',
                        'case_KRUU.pdf',
                        'case_OaklandUniversity.pdf',
                        'case_oxford_archaeology.pdf',
                        'case_Skegness.pdf',
                        'case_ubuntu_johnshopkins_v2.pdf',
                        'case_ubuntu_locatrix_v1.pdf',
                        'case_Wellcome.pdf' )

        if self.lsb_release['Release'] <= 8.04:
            ps_filetype = 'PostScript document text conforming at level 3.0'
        else:
            ps_filetype = 'PostScript document text conforming DSC level 3.0, Level 2'

        for filename in conversions:

            outfilename = filename.replace('.pdf', '.ps')

            (rc, report) = testlib.cmd(["/usr/bin/pdf2ps",
                                        "./data/" + filename,
                                        os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid PostScript file
            self._check_mime_type(outfilename, ps_filetype)

    def test_gs(self):
        '''Test gs executable(s)'''

        gs_bins = []
        if self.lsb_release['Release'] == 6.06:
            # Binaries split prior to Gutsy
            gs_bins = ['gs-esp', 'gs-gpl']
        else:
            gs_bins = ['gs']

        errors = 0
        errstr = ""
        for util in gs_bins:
            rc, report = testlib.cmd([util, '-sDEVICE=nullpage', '-dNOPAUSE', '--', self.ps])
            expected = 0
            if rc != expected:
                result = '\'%s\' returned exit code %d, expected %d\n' % \
                         (util, rc, expected)
                errstr = errstr + result + report
                errors += 1

        self.assertEquals(errors, 0, errstr)


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(GhostscriptTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(GhostscriptPrivateTests))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
