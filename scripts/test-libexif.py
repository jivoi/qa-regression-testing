#!/usr/bin/python
#
#    test-libexif.py quality assurance test script for libexif
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install exif  && ./test-libexif.py -v'
'''

# QRT-Depends: libexif private/qrt/libexif.py
# QRT-Packages: exif

import unittest, sys
import testlib, tempfile

try:
    from private.qrt.libexif import PrivateLibexifTest
except ImportError:
    class PrivateLibexifTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibexifTest(testlib.TestlibCase, PrivateLibexifTest):
    '''Test libexif.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.date_time_tag = 'Date and Time (original)'
        if self.lsb_release['Release'] >= 11.04:
            self.date_time_tag = 'Date and Time (Original)'

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _read_tags(self,filename):
        rc, output = testlib.cmd(['exif','-m',filename])
        self.assertEquals(rc, 0, output)
        tags = dict()
        for line in output.splitlines():
            field, value = line.strip().split('\t',1)
            tags.setdefault(field, value)
        return tags

    def test_exif_read_tags(self):
        '''Read EXIF tag values'''

        tags = self._read_tags('libexif/good.jpg')
        self.assertEquals(tags['User Comment'], 'This is an EXIF comment', tags['User Comment'])
        self.assertEquals(tags[self.date_time_tag], '2007:09:17 09:30:55', tags[self.date_time_tag])

    def test_exif_set_tag(self):
        '''Set EXIF tag value'''

        newjpg = tempfile.NamedTemporaryFile(suffix='.jpg',prefix='libexif-test-')
        self.assertShellExitEquals(0, ['exif','--ifd=EXIF','--tag','0x9003','--set-value=2008:10:14 14:14:15','-o',newjpg.name,'libexif/good.jpg'])

        tags = self._read_tags(newjpg.name)
        # exif isn't able to change comments yet?
        #self.assertEquals(tags['User Comment'], 'Altered comment here', tags['User Comment'])
        self.assertEquals(tags['User Comment'], 'This is an EXIF comment', tags['User Comment'])
        self.assertEquals(tags[self.date_time_tag], '2008:10:14 14:14:15', tags[self.date_time_tag])

if __name__ == '__main__':
    unittest.main()
