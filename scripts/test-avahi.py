#!/usr/bin/python
#
#    test-avahi.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
#    Author: Kees Cook <kees@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
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
# QRT-Packages: avahi-daemon avahi-utils python-gdbm python-dbus python-avahi
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'edgy':
        schroot -c edgy -u root -- sh -c 'apt-get -y install avahi-daemon avahi-utils python-gdbm python-dbus python-avahi && echo "AVAHI_DAEMON_START=1" >> /etc/default/avahi-daemon && /etc/init.d/avahi-daemon restart && ./test-avahi.py -v'

    Notes:
      Dapper: python2.4-dbus and python2.4-avahi
'''

import unittest, os, sys, time, re
import testlib
import dbus
import avahi

class AvahiTest(unittest.TestCase):
    '''Test Avahi functionality.'''

    def setUp(self):
        '''Setup Avahi testing'''

        # Figure out which version of Avahi utils are available
        rc, output = testlib.cmd(['/usr/bin/avahi-browse','--help'])
        self.assertEquals(rc,0)

        self.avahi_terminate = False
        if 'Terminate' in output:
            self.avahi_terminate = True

        # for dbus tests
        self.group = None
        self.server = None
        self.bus = None
        self.serviceName = "Demo Service"
        self.serviceType = "_demo._tcp"
        self.servicePort = 12345
        self.serviceTXT = "test avahi with dbus"
        self.domain = ""
        self.host = ""

        self.pidfile = "/var/run/avahi-daemon/pid"

    def tearDown(self):
        '''Teardown mechanisms'''
        if not self.group is None:
            self.group.Reset()

        self.group = None
        self.bus = None
        self.server = None

    def _browse(self):
        if self.avahi_terminate:
            return testlib.cmd(['/usr/bin/avahi-browse','--all','-t'])
        else:
            return testlib.cmd(['/bin/sh','-c','avahi-browse --all & pid=$!; sleep 4; kill $pid'])

    def _found_service(self,output,service='.*',type='.*',domain='.*'):
        # Figure out which style of report it is
        if re.search('^Service data',output,re.MULTILINE):
            return re.search("^Service data for service '%s' of type .* \(%s\) in domain '%s'.*" % (service,type,domain),output,re.MULTILINE)
        else:
            return re.search('%s\s+%s\s+%s' % (service,type,domain),output,re.MULTILINE)

    def test_avahi_daemon(self):
        '''Test Avahi daemon registrations'''

        rc, output = self._browse()
        self.assertEquals(rc, 0)
        self.assertTrue(self._found_service(output,'.*','Workstation','local'))

    def test_avahi_register_client(self):
        '''Test Avahi client registrations'''

        publisher = os.fork()
        if publisher == 0:
            args = ['/bin/sh','-c','/usr/bin/avahi-publish-service "Unit Test" _http._tcp 12345 >/dev/null 2>&1']
            os.execv(args[0],args)
            sys.exit(0)

        rc, output = self._browse()

        # Kill publisher now, so it always gets cleaned up even on test failure
        os.kill(publisher,15)
        os.waitpid(publisher,0)

        self.assertEquals(rc, 0)
        self.assertTrue(self._found_service(output,'Unit Test','Web Site','local'))

    def test_avahi_register_missing(self):
        '''Test Avahi client mis-registration'''

        rc, output = self._browse()
        self.assertEquals(rc, 0)
        self.assertFalse(self._found_service(output,'Total Nonsense','Blah','DOES NOT EXIST'))

    def _add_service(self):
        '''Add a service via dbus'''
        if self.bus and self.group is None:
            self.group = dbus.Interface(
                  self.bus.get_object(avahi.DBUS_NAME, self.server.EntryGroupNew()),
                  avahi.DBUS_INTERFACE_ENTRY_GROUP)

            self.group.AddService(
                avahi.IF_UNSPEC,    #interface
                avahi.PROTO_UNSPEC, #protocol
                dbus.UInt32(0),                  #flags
                self.serviceName, self.serviceType,
                self.domain, self.host,
                dbus.UInt16(self.servicePort),
                avahi.string_array_to_txt_array(self.serviceTXT))

            self.group.Commit()
            time.sleep(60)

    def test_avahi_dbus(self):
        '''Test Avahi dbus registrations'''
        publisher = os.fork()
        if publisher == 0:
            self.bus = dbus.SystemBus()
            self.server = dbus.Interface(
                   self.bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER ),
                   avahi.DBUS_INTERFACE_SERVER )
            self._add_service()
            sys.exit(0)

        # give a little time to register
        time.sleep(5)
        rc, output = self._browse()

        # kill publisher now
        os.kill(publisher, 15)
        os.waitpid(publisher, 0)

        self.assertEquals(rc, 0)
        self.assertTrue(self._found_service(output, '.*', self.serviceType, 'local'), output)

    def test_daemon(self):
        '''Test Avahi daemon running'''
        warning = "Could not find pidfile '%s'" % (self.pidfile)
        self.assertTrue(os.path.exists(self.pidfile), warning)
        self.assertTrue(testlib.check_pidfile("avahi-daemon", self.pidfile))

if __name__ == '__main__':
    unittest.main()
