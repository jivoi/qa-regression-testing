#!/usr/bin/python
#
#    test-evince.py quality assurance test script for Xine
#    Copyright (C) 2008-2013 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
  How to run in a clean virtual machine with sound enabled:
    1. apt-get -y install evince firefox apparmor-docs apparmor apparmor-utils unrar p7zip unzip texlive-extra-utils
    2. ./test-evince.py -v (as non-root)

  NOTES:
    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test.

  GUTSY:
    - well-formed.tiff is discolored
'''

# QRT-Depends: testlib_data.py private/qrt/pdfs.py
# QRT-Packages: evince firefox apparmor-docs apparmor apparmor-utils unrar p7zip|p7zip-full unzip texlive-extra-utils

import unittest, sys
import testlib
import testlib_data
import tempfile
import os
import shutil

try:
    from private.qrt.pdfs import PrivatePDFTests
except ImportError:
    class PrivatePDFTests(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class TestImages(testlib_data.DataCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['evince']
        if self.lsb_release['Release'] >= 9.10:
            self.exes.append('evince-previewer')

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_gif(self):
        '''Test GIF'''
        for exe in self.exes:
            self._cmd([exe], "gif", url=False)

    def test_jpg(self):
        '''Test JPG'''
        for exe in self.exes:
            self._cmd([exe], "jpg", url=False)

    def test_png(self):
        '''Test PNG'''
        for exe in self.exes:
            self._cmd([exe], "png", url=False)

    def test_tiff(self):
        '''Test TIFF'''
        for exe in self.exes:
            self._cmd([exe], "tif", url=False)
            self._cmd([exe], "tiff", url=False)

    def test_bmp(self):
        '''Test BMP'''
        for exe in self.exes:
            self._cmd([exe], "bmp", url=False)

    def test_pnm(self):
        '''Test PNM'''
        for exe in self.exes:
            self._cmd([exe], "pnm", url=False)

    def test_xpm(self):
        '''Test XPM'''
        for exe in self.exes:
            self._cmd([exe], "xpm", url=False)

    def test_eps(self):
        '''Test EPS'''
        for exe in self.exes:
            self._cmd([exe], "eps", url=False)


class TestDocuments(testlib_data.DataCommon, PrivatePDFTests):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['evince']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_pdf(self):
        '''Test PDF'''
        for exe in self.exes:
            self._cmd([exe], "pdf")

    def test_ps(self):
        '''Test PS'''
        for exe in self.exes:
            self._cmd([exe], "ps")

    def test_djvu(self):
        '''Test DJVU'''
        for exe in self.exes:
            self._cmd([exe], "djvu")

    def test_dvi(self):
        '''Test DVI'''
        for exe in self.exes:
            self._cmd([exe], "dvi")

    def test_comicbook(self):
        '''Test Comic Book archives'''
        for exe in self.exes:
            for ext in ['cbr', 'cbz', 'cb7', 'cbt']:
                self._cmd([exe], ext)

    def test_gz(self):
        '''Test PDF (gzipped)'''
        if self.lsb_release['Release'] < 8.04:
            self._skipped("'gz' not supported")
            return

        for exe in self.exes:
            self._cmd([exe], "pdf.gz")

    def test_bz2(self):
        '''Test PDF (bzip2ed)'''
        if self.lsb_release['Release'] < 8.04:
            self._skipped("'bzip2' not supported")
            return

        for exe in self.exes:
            self._cmd([exe], "pdf.bz2")

    # these don't really work on any released version of Ubuntu
    #def test_odp(self):
    #    '''Test ODP'''
    #    for exe in self.exes:
    #        self._cmd([exe], "odp")

class TestDocumentsBrowser(testlib_data.DataCommon):
    '''Test viewing of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.exes = ['firefox']

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_pdf(self):
        '''Test PDF from browser'''
        return self._skipped("Firefox uses internal pdf viewer now.")
        for exe in self.exes:
            self._cmd([exe], "pdf", limit=1)

    def test_ps(self):
        '''Test PS from browser'''
        for exe in self.exes:
            self._cmd([exe], "ps", limit=1)

    def test_djvu(self):
        '''Test DJVU from browser'''
        for exe in self.exes:
            self._cmd([exe], "djvu", limit=1)

class TestMisc(testlib_data.DataCommon):
    '''Test various tasks'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_data.DataCommon._setUp(self)
        self.types = ['tif', 'tiff', 'pdf', 'ps', 'pdf.gz', 'pdf.bz2', 'djvu', 'dvi', 'eps']
        if self.lsb_release['Release'] < 11.10: # 11.10 and later don't do images
            self.types += ['gif', 'jpg', 'png', 'bmp', 'pnm', 'xpm']
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.apparmor_denied_file = ""
        self.apparmor_allowed_file = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)
        if os.path.exists(self.apparmor_denied_file):
            os.unlink(self.apparmor_denied_file)
        if os.path.exists(self.apparmor_allowed_file):
            os.unlink(self.apparmor_allowed_file)

    def _first_file(self, ext):
        path = ""
        for f in self.files:
            name = os.path.basename(f)
            path = os.path.join(os.path.join(os.getcwd(), 'data', name))
            if not os.path.exists(path):
                self._skipped("Couldn't find %s" % (path))
                continue
            if name.endswith('.' + ext):
                break

        return path

    def test_thumbnailer(self):
        '''Test thumbnailer'''
        thumb = os.path.join(self.tmpdir, "thumb.png")
        print ""
        for type in self.types:
            if os.path.exists(thumb):
                os.unlink(thumb)

            print "  %s" % (type.upper())
            rc, report = testlib.cmd(['evince-thumbnailer', self._first_file(type), thumb])
            self.assertTrue(os.path.exists(thumb), "Could not find thumbnail for type '%s'" % type)

    def test_previewer(self):
        '''Test previewer'''
        if self.lsb_release['Release'] < 9.10:
            self._skipped("previewer only in 9.10 and above")
            return

        for type in self.types:
            self._cmd(['evince-previewer'], type, url=False, limit=1)

    def test_apparmor_confinement(self):
        '''Test apparmor confinement'''
        if self.lsb_release['Release'] < 9.10:
            self._skipped("AppArmor profile only in 9.10 and above")
            return

        print ""
        self.apparmor_denied_file = os.path.join(os.environ['HOME'], '.ssh/foo.pdf')
        shutil.copy(self._first_file('pdf'), self.apparmor_denied_file)
        for exe in ['evince', 'evince-previewer']:
            print "  %s: %s (should be denied)" % (self.apparmor_denied_file, exe)
            rc, report = testlib.cmd([exe, self.apparmor_denied_file])
            result = "%s opened %s" % (exe, self.apparmor_denied_file)
            self.assertTrue('Permission denied' in report, result + report)

        self.apparmor_allowed_file = os.path.join(os.environ['HOME'], 'Desktop/foo.pdf')
        shutil.copy(self._first_file('pdf'), self.apparmor_allowed_file)
        for exe in ['evince', 'evince-previewer']:
            print "  %s: %s (should be allowed)" % (self.apparmor_allowed_file, exe)
            rc, report = testlib.cmd([exe, self.apparmor_allowed_file])
            expected = 0
            result = 'Got exit code %d\n' % (rc)
            self.assertTrue(rc == 0, result + report)

        if os.path.exists(self.apparmor_allowed_file):
            os.unlink(self.apparmor_allowed_file)
        if os.path.exists(self.apparmor_denied_file):
            os.unlink(self.apparmor_denied_file)

        print "  %s: %s (deny)" % (self.apparmor_denied_file, 'evince-thumbnailer')
        rc, report = testlib.cmd(['evince-thumbnailer', self._first_file('pdf'), self.apparmor_denied_file])
        self.assertFalse(os.path.exists(self.apparmor_denied_file), "Found denied file: '%s'" % self.apparmor_denied_file)

        print "  %s: %s (allow)" % (self.apparmor_allowed_file, 'evince-thumbnailer')
        rc, report = testlib.cmd(['evince-thumbnailer', self._first_file('pdf'), self.apparmor_allowed_file])
        self.assertTrue(os.path.exists(self.apparmor_allowed_file), "Could not find allowed file: '%s'" % self.apparmor_allowed_file)

        techdoc = "/usr/share/doc/apparmor-docs/techdoc.pdf.gz"
        if not os.path.exists(techdoc):
            self._skipped("Skipping %s" % (techdoc))
        else:
            for exe in ['evince', 'evince-previewer']:
                print "  %s: %s (should be allowed)" % (techdoc, exe)
                rc, report = testlib.cmd([exe, techdoc])
                expected = 0
                result = 'Got exit code %d\n' % (rc)
                self.assertTrue(rc == 0, result + report)

    def test_apparmor(self):
        '''Test apparmor'''
        for exe in ['evince', 'evince-previewer', 'evince-thumbnailer']:
            rc, report = testlib.check_apparmor(exe, 9.10, is_running=False)
            if rc < 0:
                return self._skipped(report)

            expected = 0
            result = 'Got exit code %d, expected %d for \'%s\'\n' % (rc, expected, exe)
            self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    suite = unittest.TestSuite()
    ubuntu_version = testlib.manager.lsb_release["Release"]
    if ubuntu_version < 11.10: # 11.10 and later don't do images
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestImages))

    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestMisc))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestDocumentsBrowser))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestDocuments))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
