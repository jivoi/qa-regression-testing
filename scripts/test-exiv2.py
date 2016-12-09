#!/usr/bin/python
#
#    test-exiv2.py quality assurance test script for exiv2
#    Copyright (C) 2008 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install exiv2  && ./test-exiv2.py -v'
'''

# QRT-Depends: exiv2 private/qrt/exiv2.py
# QRT-Packages: exiv2

import unittest, sys, shutil
import testlib, tempfile

try:
    from private.qrt.exiv2 import PrivateExiv2Test
except ImportError:
    class PrivateExiv2Test(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class Exiv2Test(testlib.TestlibCase, PrivateExiv2Test):
    '''Test exiv2.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _read_tags(self,filename):
        rc, output = testlib.cmd(['exiv2','pr',filename])
        self.assertEquals(rc, 0, output)
        tags = dict()
        for line in output.splitlines():
            line = line.strip()
            if len(line) == 0:
                continue
            try:
                field, value = line.split(':',1)
            except:
                raise ValueError, "Line '%s' lacks ':' delimiter" % (line)
            tags.setdefault(field.strip(), value.strip())
        return tags

    def test_exif_read_tags(self):
        '''Read EXIF tag values'''

        tags = self._read_tags('exiv2/good.jpg')
        self.assertEquals(tags['Exif comment'], 'This is an EXIF comment', tags['Exif comment'])
        self.assertEquals(tags['Image timestamp'], '2007:09:17 09:30:55', tags['Image timestamp'])

    def test_exif_set_tag(self):
        '''Set EXIF tag value'''

        newjpg = tempfile.NamedTemporaryFile(suffix='.jpg',prefix='exiv2-test-')
        self.assertEquals(None,shutil.copy('exiv2/good.jpg',newjpg.name))
        self.assertShellExitEquals(0, ['exiv2','-Mset Exif.Photo.DateTimeOriginal 2008:10:10 10:10:10',newjpg.name])

        tags = self._read_tags(newjpg.name)
        self.assertEquals(tags['Image timestamp'], '2008:10:10 10:10:10', tags['Image timestamp'])

    def test_nikon_lense_crash(self):
        '''Invalid Nikon Lense EXIF does not crash (CVE-2008-2696)'''
        self.assertShellExitEquals(0, ['exiv2','pr','-pt','exiv2/CVE-2008-2696.jpg'])

if __name__ == '__main__':
    unittest.main()
