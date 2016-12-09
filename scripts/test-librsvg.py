#!/usr/bin/python
#
#    test-librsvg.py quality assurance test script for librsvg
#    Copyright (C) 2011 Canonical Ltd.
#    Author: Kees Cook <kees@canonical.com>
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
#
# packages required for test to run:
# QRT-Packages: file imagemagick eog
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: librsvg

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file imagemagick eog && ./test-librsvg.py -v'
'''


import unittest, sys, tempfile, os
import testlib

try:
    from private.qrt.librsvg import PrivateLibrsvgTest
except ImportError:
    class PrivateLibrsvgTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibrsvgTest(testlib.TestlibCase, PrivateLibrsvgTest):
    '''Test librsvg.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        os.chdir('librsvg')

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def _test_render(self, svg_filename):
        '''Convert to jpg to check for conversion warnings'''
        jpg_tmp = tempfile.NamedTemporaryFile(prefix='convert-',suffix='.jpg')
        jpg_filename = jpg_tmp.name

        self.assertFileType(svg_filename, 'SVG Scalable Vector Graphics image')
        self.assertShellExitEquals(0, ["eog", svg_filename])

        # Try a to-JPG conversion to catch rendering problems
        self.assertShellOutputEquals("",
                                     ["/usr/bin/convert",
                                      svg_filename,
                                      jpg_filename],
                                     expected=0)
        self.assertFileType(jpg_filename, 'JPEG image data.*')
        self.assertShellExitEquals(0, ["eog", jpg_filename])

    def test_complex_svg(self):
        '''normal SVG will render'''
        self._test_render("simple.svg")
        if self.lsb_release['Release'] > 10.04:
            self._test_render("complex.svg")

    def test_filters(self):
        '''misnamed filters do not run arbitrary code (CVE-2011-3146)'''
        self._test_render("good-filter.svg")
        self._test_render("bad-filter.svg")
        self._test_render("big-filter.svg")

if __name__ == '__main__':
    # simple
    unittest.main()
