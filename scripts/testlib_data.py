#!/usr/bin/python
#
#    testlib_data.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
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
#    along with this program.  If not, see <httpd://www.gnu.org/licenses/>.
#
'''
Classes to help with testing image and document viewers. Simply put datafiles
into data/ relative to this script, then can do:

#!/usr/bin/python

import unittest, subprocess, sys
import testlib
import testlib_data

class TestImages(testlib_data.DataCommon):
    def setUp(self):
        testlib_data.DataCommon._setUp(self)
        self.exes = ['YOUR EXECUTABLE NAME']

    def tearDown(self):
        pass

    def test_FILETYPE(self):
        \'''Test FILETYPE\'''
        for exe in self.exes:
            self._cmd([exe], "FILE EXTENSION")

    ...

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestImages))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestDocuments))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
'''

# QRT-Depends: data

import os
import sys
import tempfile
import shutil
import testlib

class DataCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self, dir='./data'):
        '''Setup'''
        self.release = testlib.ubuntu_release()
        self.assertFalse(os.getuid() == 0, "ERROR: must not be root")
        self.files = os.listdir(dir)
        self.files.sort()

    def _cmd(self, command, extension, limit=0, url=True, expected_rc=0,
             dir='data', skip=[]):
        '''Execute command on files with the specified extension'''
        count = 0
        for f in self.files:
            name = os.path.basename(f)
            if name in skip:
                continue

            path = os.path.join(os.getcwd(), dir, name)
            if dir.startswith('/'):
                path = os.path.join(dir, name)

            if url==True:
                if path.startswith('/'):
                    fq_path = "file://" + path
                else:
                    fq_path = "file:///" + path
            else:
                fq_path = path

            if (limit == 0 or count < limit) and name.endswith('.' + extension):
                if not os.path.exists(path):
                    self._skipped("Couldn't find %s" % (path))
                    continue

                print >>sys.stdout, "%s" % (name),
                sys.stdout.flush()
                rc, report = testlib.cmd(command + [fq_path])
                result = 'Got exit code %d, expected %d\n' % (rc, expected_rc)
                self.assertEquals(expected_rc, rc, result + report)
                count += 1

        print >>sys.stdout, "... ",
        sys.stdout.flush()

    def cp_data_to_tmpdir(self, extension, dir='data'):
        '''Copy files with the specificied extension to a temporary directory'''
        tmpdir = tempfile.mkdtemp(prefix='testlib_data', dir='/tmp')
        for f in self.files:
            name = os.path.basename(f)
            if name.endswith('.' + extension):
                path = os.path.join(os.getcwd(), dir, name)
                shutil.copy2(path, tmpdir) 

        return tmpdir

