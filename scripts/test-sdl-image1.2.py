#!/usr/bin/python
#
#    test-sdl-image1.2.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
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

'''
    How to run against a clean schroot named 'gutsy':
        schroot -c gutsy -u root -- sh -c 'apt-get -y install libsdl-image1.2 libjpeg62 libtiff4 && ./test-sdl-image1.2.py -v'
'''

# QRT-Depends: data sdl-image1.2
# QRT-Packages: libsdl-image1.2 libsdl-image1.2-dev

import unittest, glob, os.path
import testlib

class SDLImageTest(testlib.TestlibCase):
    '''Test SDL image.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.loader = 'sdl-image1.2/sdl-image-load'

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _load_image(self,filename,expected=0):
        self.assertTrue(os.path.exists(filename))
        rc, out = testlib.cmd([self.loader, filename])
        self.assertEqual(rc,expected,"Loading: %s\nError: %s\n"%(filename,out))

    def test_00_build(self):
        self.announce("%s" % (self.gcc_version))

        self.assertShellExitEquals(0, ["make", "clean", "-C", "sdl-image1.2"])
        self.assertShellExitEquals(0, ["make", "-C", "sdl-image1.2"])
        self.assertTrue(os.path.exists(self.loader))

    def test_image_loading(self):
        '''Test loading known-good images'''
        # TODO: accurate for 11.04-- need to check other releases
        not_supported = [ '.gd', '.jpc', '.ras', '.emf', '.wmf', '.jp2', '.gd2', '.eps' ]
        for img in glob.glob('./data/well-formed.*'):
            skip = False
            for ext in not_supported:
                if img.endswith(ext):
                    skip = True
            if skip:
                continue
            self._load_image(img)

    def test_z_bad_gif(self):
        '''Test fixes for CVE-2007-6697'''
        self._load_image('sdl-image1.2/CVE-2007-6697.gif',1)

if __name__ == '__main__':
    unittest.main()
