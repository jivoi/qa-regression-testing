#!/usr/bin/python
#
#    test-cmake.py quality assurance test script for cmake
#    Copyright (C) 2010 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: cmake build-essential lsb-release
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: cmake

'''
    TODO:
      Integrate the build tests in the source Tests/ directory
'''


import unittest, subprocess, sys, os
import testlib
import tempfile
import shutil

class CmakeTest(testlib.TestlibCase):
    '''Test cmake.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_tutorial(self):
        '''Test tutorial'''
        version = "2.8"
        if self.lsb_release['Release'] < 8.10:
            version = "2.4"
        elif self.lsb_release['Release'] < 10.04:
            version = "2.6"
        tarball = "%s.tar.gz" % (version)

        shutil.copy(os.path.join('./cmake', tarball), self.tmpdir)
        os.chdir(self.tmpdir)
        subprocess.call(['tar', '-zxf', os.path.join('./', tarball)])

        topdir = os.path.join(self.tmpdir, version)
        print ""
        dirs = os.listdir(topdir)
        dirs.sort()
        for d in dirs:
            print "  %s" % d
            os.chdir(os.path.join(topdir, d))
            rc, report = testlib.cmd(['cmake', '.'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertTrue(rc == expected, result + report)

            for i in ['works', 'done', 'Configuring done', 'Generating done', 'Build files have been written to']:
                result = "Could not find '%s' in report:\n" % (i)
                self.assertTrue(i in report, result + report)

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CmakeTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
