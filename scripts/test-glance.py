#!/usr/bin/python
#
#    test-glance.py quality assurance test script for glance
#    Copyright (C) 2013 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: python-glance
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: glance/
# privilege required for the test to run (remove line if running as user is okay):

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-<script>.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-<script>.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-<script>.tar.gz
    # cd /tmp/qrt-test-<script> ; ./install-packages ./test-<script>.py
    # ./test-<script>.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import unittest
import testlib

class GlanceTest(testlib.TestlibCase):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_valid_swift_store_uri(self):
        '''Test valid swift store uris'''
        user = "someuser"
        passwd = "secret"
        valid_uris = [
              'swift+http://%s:%s@authurl.com/v1/container/obj' % (user, passwd),
              'swift+https://%s:%s@authurl.com/v1/container/obj' % (user, passwd),
             ]
        if self.lsb_release['Release'] < 12.10:
            valid_uris.append('swift://account:%s:%s@authurl.com/container/obj' % (user, passwd))

        print ""
        for url in valid_uris:
            print "  %s" % url
            rc, report = testlib.cmd(['./glance/test-store-uri.py', str(self.lsb_release['Release']), url])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertTrue(rc == expected, result + report)

    def test_CVE_2013_0212(self):
        '''Test CVE-2013-0212'''
        user = "someuser"
        passwd = "secret"
        invalid_uris = [
                'swift://%s:%s@http://authurl.com/v1/container/obj' % (user, passwd), # two '://'
                'swift+https://%s@authurl.com/v1/container/obj' % user, #Invalid creds
               ]

        print ""
        for url in invalid_uris:
            print "  %s" % url
            rc, report = testlib.cmd(['./glance/test-store-uri.py', str(self.lsb_release['Release']), url])
            expected = 1
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertTrue(rc == expected, result + report)

            self.assertFalse(user in report, "Found '%s' in:\n%s" % (user, report))
            self.assertFalse(passwd in report, "Found '%s' in:\n%s" % (passwd, report))

        

if __name__ == '__main__':
    # simple
    unittest.main()
