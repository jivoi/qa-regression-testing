#!/usr/bin/python
#
#    test-libnss-db.py quality assurance test script for libnss-db
#    Copyright (C) 2010 Canonical Ltd.
#    Author: 
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
# QRT-Packages: libnss-db sudo
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/LibNSSDB.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install libnss-db sudo && ./test-libnss-db.py -v'
'''


import unittest, sys, os, glob, tempfile, shutil
import testlib

try:
    from private.qrt.LibNSSDB import PrivateLibNSSDBTest
except ImportError:
    class PrivateLibNSSDBTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibNSSDBTest(testlib.TestlibCase, PrivateLibNSSDBTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.nsswitch = '/etc/nsswitch.conf'
        contents = file(self.nsswitch).read().replace('compat','db files')
        testlib.config_replace(self.nsswitch,contents)

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
        testlib.config_restore(self.nsswitch)

    def test_00_cleanup(self):
        '''Clean up DB cache'''
        db = glob.glob('/var/lib/misc/*.db')
        if len(db) > 0:
            self.assertShellExitEquals(0, ['rm']+db)

    def test_10_disappeared_user_stays(self):
        '''Users are actually being cached in db'''
        user = testlib.TestUser()
        login = user.login
        uid = user.uid
        gid = user.gid

        # Verify user disappears from "files" as expected...
        expected = 'uid=%d(%s) gid=%d(%s) groups=%d(%s)\n' % (uid, login, gid, login, gid, login)
        self.assertShellOutputEquals(expected, ['id',login])
        user = None
        self.assertShellOutputEquals('id: %s: No such user\n' % (login), ['id',login])


        user = testlib.TestUser()
        login = user.login
        uid = user.uid

        os.chdir('/var/lib/misc')
        self.assertShellExitEquals(0, ['make'])

        # Verify user stays in db until we rebuild
        expected = 'uid=%d(%s) gid=%d(%s) groups=%d(%s)\n' % (uid, login, gid, login, gid, login)
        self.assertShellOutputEquals(expected, ['id',login])
        user = None
        self.assertShellOutputEquals(expected, ['id',login])


    def test_20_environment_leak(self):
        '''Does not leak DB_CONFIG contents (CVE-2010-0826)'''

        user = testlib.TestUser()
        try:
            line1 = file('/etc/shadow').read().splitlines()[0].split(":")[0]
            tmpdir = tempfile.mkdtemp(prefix='dbleak-')
            os.chdir(tmpdir)
            os.chown(tmpdir,user.uid,user.gid)

            self.assertShellExitEquals(0, ['sudo','-u',user.login,"ln","-s","/etc/shadow",'DB_CONFIG'])
            rc, output = testlib.cmd(['sudo','-u',user.login,"sudo"])
            self.assertTrue('incorrect name-value pair' not in output,output)
            self.assertTrue(line1 not in output,output)
        finally:
            os.chdir('/')
            shutil.rmtree(tmpdir)


if __name__ == '__main__':
    testlib.require_sudo()
    # simple
    os.environ['LANG']='C'
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(LibNSSDBTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
