#!/usr/bin/python
#
#    test-open-iscsi.py quality assurance test script for open-iscsi
#    Copyright (C) 2011 Canonical Ltd.
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
# QRT-Packages: open-iscsi
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-PKG.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-PKG.py -v'


    NOTES:
    - currently only tested on Ubuntu 8.04
'''


import unittest, sys, os
import testlib
import time

# There are setup based on README.multipurpose-vm. Feel free to override.
remote_server = ''
username = 'ubuntu'
password = 'passwd'
username_in = 'ubuntu'
password_in = 'ubuntupasswd'
initiatorname = 'iqn.2009-10.com.example.hardy-multi:iscsi-01'

try:
    from private.qrt.OpenIscsi import PrivateOpenIscsiTest
except ImportError:
    class PrivateOpenIscsiTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class OpenIscsiTest(testlib.TestlibCase, PrivateOpenIscsiTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.pidfile = "/var/run/iscsid.pid"
        self.exe = "/sbin/iscsid"
        self.daemon = testlib.TestDaemon("/etc/init.d/open-iscsi")
        self.initiatorname_iscsi = '/etc/iscsi/initiatorname.iscsi'
        self.iscsid_conf = '/etc/iscsi/iscsid.conf'

    def tearDown(self):
        '''Clean up after each test_* function'''
        global remote_server
        global initiatorname

        # If remote server is setup, convert back to manual, logout, remove
        # testlib configs and restart (in that order)
        if remote_server != '':
            testlib.cmd(['iscsiadm', '-m', 'node', '--targetname', initiatorname, '-p', '%s:3260' % remote_server, '--op=update', '--name', 'node.startup', '--value=manual'])
            testlib.cmd(['iscsiadm', '-m', 'node', '--targetname', initiatorname, '-p', '%s:3260' % remote_server, '--op=update', '--name',  'node.conn[0].startup', '--value=manual'])
            testlib.cmd(['iscsiadm', '-m', 'node', '--targetname', initiatorname, '-p', '%s:3260' % remote_server, '--logout'])

        testlib.config_restore(self.initiatorname_iscsi)
        testlib.config_restore(self.iscsid_conf)
        self.daemon.restart()

    def test_daemon(self):
        '''Test iscsid'''
        self.assertTrue(self.daemon.stop())
        time.sleep(2)
        self.assertFalse(testlib.check_pidfile(self.exe, self.pidfile))

        self.assertTrue(self.daemon.start())
        time.sleep(2)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))

        self.assertTrue(self.daemon.restart())
        time.sleep(2)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))

    def test_discovery(self):
        '''Test iscsi_discovery'''
        # we didn't set this up to actually do anything, so expect failures
        remote_server = '127.0.0.1'

        rc, report = testlib.cmd(["/sbin/iscsi_discovery", remote_server])
        expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for i in ['starting discovery to %s' % remote_server,
                  'iscsiadm: cannot make connection to %s' % remote_server,
                  'failed to discover targets at %s' % remote_server]:
            result = "Could not find '%s' in report:\n" % i
            self.assertTrue(i in report, result + report)

    def test_discovery_with_server(self):
        '''Test iscsi_discovery to remote server'''
        global remote_server
        global username
        global password
        global username_in
        global password_in
        global initiatorname

        if remote_server == '':
            return self._skipped("--remote-server not specified")

        contents = '''
InitiatorName=%s
InitiatorAlias=ubuntu
''' % (initiatorname)
        testlib.config_replace(self.initiatorname_iscsi, contents, True)

        contents = '''
node.session.auth.authmethod = CHAP
node.session.auth.username = %s
node.session.auth.password = %s
node.session.auth.username_in = %s
node.session.auth.password_in = %s

discovery.sendtargets.auth.authmethod = CHAP
discovery.sendtargets.auth.username = %s
discovery.sendtargets.auth.password = %s
discovery.sendtargets.auth.username_in = %s
discovery.sendtargets.auth.password_in = %s
''' % (username, password, username_in, password_in, username, password, username_in, password_in)
        testlib.config_replace(self.iscsid_conf, contents, True)

        self.assertTrue(self.daemon.restart())
        time.sleep(2)
        self.assertTrue(testlib.check_pidfile(os.path.basename(self.exe), self.pidfile))

        rc, report = testlib.cmd(["/sbin/iscsi_discovery", remote_server])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for i in ['starting discovery to %s' % remote_server,
                  'Testing iser-login to target %s portal %s' % (initiatorname, remote_server),
                  'starting to test tcp-login to target %s portal %s' % (initiatorname, remote_server),
                  'discovered 1 targets at %s, connected to 1' % remote_server]:
            result = "Could not find '%s' in report:\n" % i
            self.assertTrue(i in report, result + report)

if __name__ == '__main__':
    import optparse
    parser = optparse.OptionParser()
    parser.add_option("-v", "--verbose", dest="verbose", help="Verbose", action="store_true")
    parser.add_option("-s", "--remote-server", dest="remote_server", help="Specify host with available iSCSI volumes", metavar="HOST")

    parser.add_option("-n", "--initiatorname", dest="initiatorname", help="Specify initiatorname for use with --remote-server", metavar="NAME")

    parser.add_option("--password", dest="password", help="Specify password for use with --remote-server", metavar="PASS")
    parser.add_option("--password-in", dest="password_in", help="Specify password_in for use with --remote-server", metavar="PASS")

    parser.add_option("--username", dest="username", help="Specify username for use with --remote-server", metavar="USER")
    parser.add_option("--username-in", dest="username_in", help="Specify username_in for use with --remote-server", metavar="USER")

    (options, args) = parser.parse_args()

    if options.remote_server:
        remote_server = options.remote_server

        if options.username:
            username = options.username
        if options.password:
            password = options.password
        if options.username_in:
            username_in = options.username_in
        if options.password_in:
            password_in = options.password_in
        if options.initiatorname:
            initiatorname = options.initiatorname
        print "Connecting to remote server with:"
        print " host = %s " % remote_server
        print ' initiatorname = %s' % initiatorname
        print ' username = %s' % username
        print ' password = %s' % password
        print ' username_in = %s' % username_in
        print ' password_in = %s' % password_in

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpenIscsiTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
