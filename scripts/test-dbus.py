#!/usr/bin/python
#
#    test-dbus.py quality assurance test script
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#            Marc Deslauriers <marc.deslauriers@canonical.com>
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

'''
    IMPORTANT:
    Requires launching with dbus-launch and running within an X session

    Agh: this file can't be named "dbus.py" because the "import dbus" below
    ends up being recursive?!

    TODO:
    - go through https://wiki.ubuntu.com/DebuggingDBus and identify test cases
'''

# QRT-Depends: dbus
# QRT-Packages: build-essential pkg-config libdbus-1-dev dbus-x11 libdbus-glib-1-dev python-gobject python-dbus
# QRT-Privilege: root

import unittest, shutil, os, os.path, sys, time, atexit
import tempfile, testlib

import gobject
import dbus
import dbus.service

use_private = True
try:
    from private.qrt.dbus import DBusPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"


if getattr(dbus, 'version', (0,0,0)) >= (0,41,0):
    import dbus.glib

# Listener goo, to run in parallel to the unitests

class HelloWorldObject(dbus.service.Object):
    def __init__(self, bus_name, object_path='/com/ubuntu/HelloWorldObject'):
        dbus.service.Object.__init__(self, bus_name, object_path)

    @dbus.service.method('com.ubuntu.HelloWorldIFace')
    def hello(self):
        return 'Hello from the HelloWorldObject'

class DBusListener:
    def __init__(self):
        self.listener_pid = os.fork()
        if self.listener_pid == 0:
            try:
                bus_name = dbus.service.BusName('com.ubuntu.HelloWorld', bus=dbus.SessionBus())
                object = HelloWorldObject(bus_name)

                mainloop = gobject.MainLoop()
                mainloop.run()
            except:
                pass
            sys.exit(0)
        time.sleep(1)

    def stop(self):
        if self.listener_pid>0:
            os.kill(self.listener_pid,15)
            os.waitpid(self.listener_pid,0)


class DBusTest(testlib.TestlibCase):
    '''Test dbus functionality.'''

    def setUp(self):
        self.session_bus = dbus.SessionBus()
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="dbus-")

    def tearDown(self):
        self.session_bus = None
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_dbus_listeners(self):
        '''Test dbus listener registration'''

        proxy_obj = self.session_bus.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
        self.dbus_iface = dbus.Interface(proxy_obj, 'org.freedesktop.DBus')
        listeners = self.dbus_iface.ListNames()

        self.assertTrue('org.freedesktop.DBus' in listeners)
        self.assertTrue('com.ubuntu.HelloWorld' in listeners)
        self.assertFalse('com.ubuntu.HelloWorldMissing' in listeners)

    def test_dbus_missing(self):
        '''Test dbus exceptions on missing objects'''
        proxy_obj = self.session_bus.get_object( 'com.ubuntu.HelloWorld', '/com/ubuntu/HelloWorldObjectMissing')
        iface = dbus.Interface(proxy_obj, 'com.ubuntu.HelloWorldIFaceMissing')
        self.assertRaises(dbus.DBusException,iface.hello)

    def test_iface_hello(self):
        '''Test dbus object send/receive'''

        proxy_obj = self.session_bus.get_object('com.ubuntu.HelloWorld', '/com/ubuntu/HelloWorldObject')
        iface = dbus.Interface(proxy_obj, 'com.ubuntu.HelloWorldIFace')

        self.assertEquals(iface.hello(),'Hello from the HelloWorldObject')
        self.assertRaises(dbus.DBusException,iface.no_such_function)

    def test_signatures(self):
        '''Test signature validation (CVE-2008-3834) and (CVE-2009-1189)'''

        cfile = tempfile.NamedTemporaryFile(suffix='.c', prefix='dbus-test-', dir=self.tempdir)
        cfile.write('''
#include <stdio.h>
/* kill Dapper errors */
#define DBUS_API_SUBJECT_TO_CHANGE
#include <dbus/dbus.h>

int main ()
{
   return !dbus_signature_validate("a{(ii)i}", NULL);
}
''')
        cfile.flush()
        exe = '%s.exe' % (cfile.name)

        self.assertShellExitEquals(0,['sh','-c','gcc $(pkg-config --cflags --libs dbus-1) -o %s %s $(pkg-config --libs dbus-1)' % (exe,cfile.name)])
        cfile.close()
        # Signature should be invalid with CVE-2009-1189 patch
        self.assertShellExitEquals(1,[exe])
        os.unlink(exe)

    def test_stack_consumption_CVE_2010_4352(self):
        '''Test stack consumption (CVE-2010-4352)'''
        source_dist = './dbus/CVE-2010-4352.c'
        source = os.path.join(self.tempdir, "CVE-2010-4352.c")
        binary = os.path.join(self.tempdir, "CVE-2010-4352")
        shutil.copy(source_dist, source)

        rc, report = testlib.cmd(['gcc', '-o', binary, '-std=gnu99', source])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        pidfile = "/var/run/dbus/pid"
        exe = "dbus-daemon"

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        if self.lsb_release['Release'] < 15.10 and not testlib.check_pidfile(exe, pidfile):
            # Let's try to leave the system in a usable state
            os.unlink(pidfile)
            testlib.cmd(['stop', 'dbus'])
            testlib.cmd(['start', 'dbus'])
            time.sleep(2)
            if not testlib.check_pidfile(exe, pidfile):
                print >>sys.stderr, "\nWARNING: could not restart dbus"
        self.assertEquals(expected, rc, result + report)

    def test_byte_order_CVE_2011_2200(self):
        '''Test byte order DoS (CVE-2011-2200)'''
        source_dist = './dbus/CVE-2011-2200.c'
        source = os.path.join(self.tempdir, "CVE-2011-2200.c")
        binary = os.path.join(self.tempdir, "CVE-2011-2200")
        shutil.copy(source_dist, source)

        self.assertShellExitEquals(0,['sh','-c','gcc $(pkg-config --cflags --libs dbus-1) $(pkg-config --cflags --libs glib-2.0) $(pkg-config --cflags --libs dbus-glib-1) -o %s %s $(pkg-config --libs dbus-1) $(pkg-config --libs glib-2.0) $(pkg-config --libs dbus-glib-1)' % (binary,source)])
        # Signature should be invalid with CVE-2009-1189 patch

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2012_3524(self):
        '''Test setuid privilege escalation (CVE-2012-3524)'''
        source_dist = './dbus/CVE-2012-3524.c'
        source = os.path.join(self.tempdir, "CVE-2012-3524.c")
        binary = os.path.join(self.tempdir, "CVE-2012-3524")
        shutil.copy(source_dist, source)

        self.assertShellExitEquals(0,['sh','-c','gcc %s $(pkg-config --cflags dbus-glib-1) $(pkg-config --libs dbus-glib-1) -o %s' % (source,binary)])


        self.assertTrue('SUDO_USER' in os.environ,
                        "Couldn't find SUDO_USER in environment!")

        # Set it setuid
        os.chmod(binary, 04755)
        # Make the temp directory readable
        os.chmod(self.tempdir, 0755)

        rc, report = testlib.cmd(['sudo', '-u', os.environ["SUDO_USER"], binary])

        self.assertTrue('Unable to autolaunch when setuid' in report,
                        "Couldn't find setuid error message in:" + report)

        self.assertFalse('Successfully got system bus' in report,
                        "Successfully launched bus! report:" + report)

        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


class DBusTestPlan(testlib.TestlibCase):
    '''Test D-Bus http://dbus.freedesktop.org/doc/dbus-test-plan.html'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = "quiltv3"
        if self.lsb_release['Release'] == 10.04:
            self.patch_system = "quilt"
        self.builder = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_zz_cleaup_source_tree(self):
        '''Cleanup downloaded source'''
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)

    def _search_for_dbus_test_terms(self):
        if self.lsb_release['Release'] >= 14.10:
            search_terms =  ['PASS: ../bus/test-bus',
                             'PASS: ../bus/test-bus-system',
                             'PASS: ../dbus/test-dbus',
                             'PASS: ../bus/test-bus-launch-helper',
                             'PASS: test-shell',
                             'PASS: test-printf',
                             'PASS: test-corrupt',
                             'PASS: test-dbus-daemon',
                             'PASS: test-dbus-daemon-eavesdrop',
                             'PASS: test-loopback',
                             'PASS: test-marshal',
                             'PASS: test-refs',
                             'PASS: test-relay',
                             'PASS: test-syntax',
                             'PASS: test-syslog',
                             'PASS: run-test.sh',
                             'PASS: run-test-systemserver.sh']
        elif self.lsb_release['Release'] >= 14.04:
            search_terms =  ['PASS: ../bus/bus-test',
                             'PASS: ../bus/bus-test-system',
                             'PASS: ../dbus/dbus-test',
                             'PASS: ../bus/bus-test-launch-helper',
                             'PASS: shell-test',
                             'PASS: test-printf',
                             'PASS: test-corrupt',
                             'PASS: test-dbus-daemon',
                             'PASS: test-dbus-daemon-eavesdrop',
                             'PASS: test-loopback',
                             'PASS: test-marshal',
                             'PASS: test-refs',
                             'PASS: test-relay',
                             'PASS: test-syntax',
                             'PASS: test-syslog',
                             'PASS: run-test.sh',
                             'PASS: run-test-systemserver.sh']
        elif self.lsb_release['Release'] >= 12.04:
            search_terms =  ['PASS: shell-test',
                             'PASS: ../bus/bus-test-system',
                             'PASS: ../dbus/dbus-test',
                             'PASS: ../bus/bus-test-launch-helper',
                             'PASS: test-corrupt',
                             'PASS: test-dbus-daemon',
                             'PASS: test-loopback',
                             'PASS: test-marshal',
                             'PASS: test-refs',
                             'PASS: test-relay',
                             'PASS: test-syslog',
                             'PASS: ../bus/bus-test',
                             'PASS: run-test-systemserver.sh',
                             'PASS: run-test.sh',
                             'PASS: test-printf']
        else: # 10.04
            search_terms =  ['PASS: shell-test',
                             'PASS: dbus-test',
                             'PASS: dbus-test',
                             'PASS: bus-test',
                             'PASS: bus-test-system',
                             'PASS: bus-test-launch-helper',
                             'PASS: run-test.sh',
                             'PASS: run-test-systemserver.sh']

        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def test_dbus_tests(self):
        '''Test D-Bus \'make check\' with --enable-tests'''
        if self.lsb_release['Release'] == 15.10:
            # This test fails in the upstream release due to two different
            # bugs. Skip it in Ubuntu 15.10.
            #  https://bugs.freedesktop.org/show_bug.cgi?id=91684
            #  https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=796167
            return self._skipped("Test fails in upstream release")

        # This test partially depends on X11 and non-X11 display servers may
        # experience failures. This is a simple (and hackish) test to check for
        # X11 support.
        x11_sock_dir = '/tmp/.X11-unix'
        x11_sock_exists = True
        if not os.path.exists(x11_sock_dir) or not os.listdir(x11_sock_dir):
            x11_sock_exists = False

        build_dir = testlib.prepare_source('dbus', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        os.chdir(build_dir)

        tests_user = self.builder.login
        if  self.lsb_release['Release'] >= 12.04 and os.environ.has_key("SUDO_USER"):
            # We need to do this as the user with the X session, otherwise on
            # 11.04 and higher the test-autolaunch script fails. Tried using
	    # xhost +SI:localuser:self.builder.login, but that didn't do
            # enough. This works fine, so no big woo.
            tests_user = os.environ["SUDO_USER"]
            testlib.cmd(['chown', '-R', tests_user, self.tmpdir])

        print ""
        print "  make clean"
        rc, report = testlib.cmd(['sudo', '-u', tests_user, 'make', 'clean'])
        print "  autoreconf"
        rc, report = testlib.cmd(['sudo', '-u', tests_user, 'autoreconf', '-f', '-i'])
        print "  configure"
        rc, report = testlib.cmd(['sudo', '-u', tests_user, './configure', '--prefix=%s' % self.tmpdir, '--enable-tests', '--enable-asserts', '--with-test-socket-dir=%s' % self.tmpdir])
        for d in 'var/run/dbus', 'share/dbus-1/services':
            rc, report = testlib.cmd(['sudo', '-u', tests_user, 'mkdir', '-p', '%s/%s' % (self.tmpdir, d)])
        print "  make (will take a while)"
        rc, report = testlib.cmd(['sudo', '-u', tests_user, 'make'])

        print "  make check (will take a while)"
        rc, report = testlib.cmd(['sudo', '-H', '-u', tests_user, 'make', 'check'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Useful to see if failure
        #print report

        if self.lsb_release['Release'] >= 16.04:
            self.assertTrue('# FAIL:  0' in report, "Found test failures in test run ouput:\n%s" % report)
            self.assertTrue('# ERROR: 0' in report, "Found test errors in test run ouput:\n%s" % report)
        else:
            self._search_for_dbus_test_terms()

class DBusBindings(testlib.TestlibCase):
    '''Test D-Bus bindings'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = "cdbs"
        if self.lsb_release['Release'] >= 12.04:
            self.patch_system = "quiltv3"
        self.builder = testlib.TestUser()#group='users',uidmin=2000,lower=True)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_dbusglib_aa_tests(self):
        '''Test dbus-glib \'make check\' with --enable-tests'''
        build_dir = testlib.prepare_source('dbus-glib', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        os.chdir(build_dir)

        print ""
        print "  make clean"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make', 'clean'])
        print "  autoreconf"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'autoreconf', '-f', '-i'])
        print "  configure"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, './configure', '--prefix=%s' % self.tmpdir, '--enable-tests', '--enable-asserts'])

        print "  make (will take a while)"
        rc, report = testlib.cmd(['sudo', '-u', self.builder.login, 'make'])

        print "  make check (will take a while)"
        rc, report = testlib.cmd(['sudo', '-H', '-u', self.builder.login, 'make', 'check'])

        expected = 0
        # This actually fails on Precise, Trusty and Utopic
        if self.lsb_release['Release'] in [12.04, 14.04, 14.10, 15.04]:
            expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Useful to see if failure
        #print report

        search_terms = ['PASS: dbus-glib-test',
                        'PASS: test-compile-nested.sh',
                        'PASS: run-peer-test.sh']

        if self.lsb_release['Release'] >= 14.10:
            search_terms += ['PASS: test-errors',
                             'PASS: test-specialized-types']

        # This actually fails on Precise, Trusty and Utopic
        if self.lsb_release['Release'] in [12.04, 14.04, 14.10, 15.04]:
            search_terms.append('FAIL: run-test.sh')
        else:
            search_terms.append('PASS: run-test.sh')

        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def test_dbusglib_zz_cleaup_source_tree(self):
        '''Cleanup downloaded source'''
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)

    def test_python_dbus_system(self):
        '''Test python dbus (system)'''
        rc, report = testlib.cmd(['./dbus/list-system-services.py'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = "org.freedesktop.DBus"
        self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def test_python_dbus_session(self):
        '''Test python dbus (session)'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec ./dbus/example-service.py >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        rc, report = testlib.cmd(['./dbus/example-client.py'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search_terms = ["dbus.Array([dbus.String(u'Hello')", '<node name="/SomeObject">', '<interface name="com.example.SampleInterface">', '<method name="HelloWorld">']
        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        rc, report = testlib.cmd(['./dbus/example-async-client.py'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search_terms = ["dbus.Array([dbus.String(u'Hello')", 'RaiseException raised an exception as expected']
        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        rc, report = testlib.cmd(['./dbus/example-client.py', '--exit-service'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search_terms = ["dbus.Array([dbus.String(u'Hello')", '<node name="/SomeObject">', '<interface name="com.example.SampleInterface">', '<method name="HelloWorld">']
        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

    def test_python_dbus_session_signals(self):
        '''Test python dbus (session signals)'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec ./dbus/example-signal-emitter.py >/dev/null 2>&1']
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

        rc, report = testlib.cmd(['./dbus/example-signal-recipient.py'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search_terms = ['Caught signal (in catchall handler) org.freedesktop.DBus.NameAcquired', 'Caught signal (in catchall handler) com.example.TestService.HelloSignal', 'com.example.TestService interface says Hello when it sent signal HelloSignal', 'Received a hello signal and it says Hello', 'Received signal (by connecting using remote object) and it says: Hello']
        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        rc, report = testlib.cmd(['./dbus/example-signal-recipient.py', '--exit-service'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search_terms = ['Caught signal (in catchall handler) org.freedesktop.DBus.NameAcquired', 'Caught signal (in catchall handler) com.example.TestService.HelloSignal', 'com.example.TestService interface says Hello when it sent signal HelloSignal', 'Received a hello signal and it says Hello', 'Received signal (by connecting using remote object) and it says: Hello', 'Caught signal (in catchall handler) org.freedesktop.DBus.NameOwnerChanged']
        for search in search_terms:
            self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

    def test_python_gdbus_session(self):
        '''TODO: Test python gdbus (session)'''

    def test_python_gdbus_system(self):
        '''TODO: Test python gdbus (system)'''

    def test_vala_dbus_session(self):
        '''TODO: Test vala dbus/glib (session)'''

    def test_vala_dbus_system(self):
        '''TODO: Test vala dbus/glib (system)'''

    def test_vala_gdbus_session(self):
        '''TODO: Test vala gdbus (session)'''

    def test_vala_gdbus_system(self):
        '''TODO: Test vala gdbus (system)'''


class DBusAppArmorCommon(testlib.TestlibCase):
    '''Common functionality and tests for AppArmor/DBus test plan
       https://wiki.ubuntu.com/SecurityTeam/Specifications/Oneiric/AppArmorDbus
    '''
    def _setUp(self, bus):
        '''Set up prior to each test_* function'''
        self.deny_expected = 0
        if self.lsb_release['Release'] >= 13.10 and self._apparmor_enabled():
            self.deny_expected = 1

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.policy_files = []
        self.listener = None # server

        self.bus = bus
        self.server = os.path.join(os.getcwd(), 'dbus/example-service.py')
        self.client = os.path.join(os.getcwd(), 'dbus/example-client.py')
        self.async_client = os.path.join(os.getcwd(), 'dbus/example-async-client.py')

        # hard-coded into example-{service,client,async-client}.py
        self.server_name = 'com.example.SampleService'
        self.server_interface = 'com.example.SampleInterface'
        self.server_path = '/SomeObject'
        self.server_member = '{HelloWorld,RaiseException,GetTuple,GetDict,Exit}'

    def _tearDown(self):
        '''Clean up after each test_* function'''
        # kill server now
        if self.listener != None:
            os.kill(self.listener, 15)
            os.waitpid(self.listener, 0)

        # remove any profiles
        if self._apparmor_enabled():
            for p in self.policy_files:
                testlib.cmd(['apparmor_parser', '-R', p])

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _load_policy(self, fn):
        '''Load AppArmor policy'''
        if not self._apparmor_enabled():
            return

        rc, report = testlib.cmd(['apparmor_parser', '-r', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _gen_policy(self, exe, fn, extra=''):
        '''Generate AppArmor policy for executable'''
        if not self._apparmor_enabled():
            return

        by_release = ''
        if self.lsb_release['Release'] >= 14.10:
            by_release += '  unix peer=(addr="@/tmp/dbus-*"),\n'

        contents = '''
#include <tunables/global>

%s {
  #include <abstractions/base>
  #include <abstractions/python>
  /usr/include/python*/** r,

  /usr/bin/env ix,
  /usr/bin/python* ix,

  capability dac_override,
  @{PROC}/[0-9]*/fd/ r,

  /{etc,var/lib/dbus}/machine-id r,
  /usr/bin/dbus-launch ux,

  %s r,

  # Rules that vary by Ubuntu release
%s

  # common
  dbus send bus=%s member={Hello,GetNameOwner,AddMatch} peer=(name=org.freedesktop.DBus),
  dbus (send receive) bus=%s interface=org.freedesktop.DBus.Introspectable member=Introspect,

  # extra
%s
}
''' % (exe, exe, by_release, self.bus, self.bus, extra)
        testlib.create_fill(fn, contents)

        self._load_policy(fn)
        self.policy_files.append(fn)

    def _peer_conditional(self, peer_name='', peer_label=''):
        '''Return the peer conditional string based on peer_name and peer_label'''
        peer=''

        if peer_name or peer_label:
            peer += ' peer=( '
            if peer_name:
                peer += 'name=%s ' % peer_name
            if peer_label:
                peer += 'label=%s ' % peer_label
            peer += ')'

        return peer

    def _extra_server_pol(self, allow_bind=True, allow_receive=True, peer_name='', peer_label=''):
        '''Return Apparmor D-Bus policy suitable for confining a server'''
        server_pol = '  dbus send bus=%s path=/org/freedesktop/DBus interface=org.freedesktop.DBus member=RequestName,' % self.bus

        if allow_bind:
            server_pol += '  dbus bind bus=%s name=%s,\n' % (self.bus, self.server_name)

        if allow_receive:
            server_pol += '  dbus receive bus=%s interface=%s path=%s member=%s' % \
                           (self.bus, self.server_interface, self.server_path, self.server_member)
            server_pol += self._peer_conditional(peer_name, peer_label) + ',\n'

        return server_pol

    def _extra_client_pol(self, allow_send=True, peer_name='', peer_label=''):
        '''Return AppArmor D-Bus policy suitable for confining a client'''
        client_pol = ''

        if allow_send:
            client_pol += '  dbus send bus=%s interface=%s path=%s member=%s' % \
                           (self.bus, self.server_interface, self.server_path, self.server_member)
            client_pol += self._peer_conditional(peer_name, peer_label) + ',\n'

        return client_pol

    def _apparmor_enabled(self):
        '''Stop/teardown apparmor'''
        aa_status = '/usr/sbin/aa-status'
        if not os.path.exists(aa_status):
            return False

        rc, report = testlib.cmd([aa_status, '--enabled'])
        if rc == 0:
            return True

        return False

    def _run_server(self):
        '''Start listener'''
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec %s >/dev/null 2>&1' % self.server]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(1)

    def _run_client(self, expected=0):
        '''Run client'''
        rc, report = testlib.cmd([self.client])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if expected == 0:
            search_terms = ["dbus.Array([dbus.String(u'Hello')", '<node name="/SomeObject">', '<interface name="com.example.SampleInterface">', '<method name="HelloWorld">']
            for search in search_terms:
                self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def _run_async_client(self, expected=0):
        '''Run async client'''
        rc, report = testlib.cmd([self.async_client])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if expected == 0:
            search_terms = ["dbus.Array([dbus.String(u'Hello')", 'RaiseException raised an exception as expected']
            for search in search_terms:
                self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def _run_client_exit(self, expected=0):
        '''Run --exit-service'''
        rc, report = testlib.cmd([self.client, '--exit-service'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if expected == 0:
            search_terms = ["dbus.Array([dbus.String(u'Hello')", '<node name="/SomeObject">', '<interface name="com.example.SampleInterface">', '<method name="HelloWorld">']
            for search in search_terms:
                self.assertTrue(search in report, "Could not find '%s' in:\n%s" % (search, report))

    def test_aa_init(self):
        '''Initialization'''
        print "DBus %s tests " % (self.bus),
        sys.stdout.flush()

    def test_aa_unconfined_to_unconfined(self):
        '''Test unconfined to unconfined'''
        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_ab_unconfined_to_confined_allow(self):
        '''Test unconfined to confined allow'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol()
        self._gen_policy(self.server, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_ac_unconfined_to_confined_deny(self):
        '''Test unconfined to confined deny'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(allow_receive=False)
        self._gen_policy(self.server, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_ad_unconfined_to_confined_peer_allow(self):
        '''Test unconfined to confined allow peer'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(peer_label='unconfined')
        self._gen_policy(self.server, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_ae_unconfined_to_confined_bad_peer(self):
        '''Test unconfined to confined bad peer'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(peer_label='unconfinedXXX')
        self._gen_policy(self.server, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_ba_confined_allow_to_unconfined(self):
        '''Test confined allow to unconfined'''
        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol()
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_bb_confined_allow_to_confined_allow(self):
        '''Test confined allow to confined allow'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol()
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol()
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_bc_confined_allow_to_confined_deny(self):
        '''Test confined allow to confined deny'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(allow_receive=False)
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol()
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_bd_confined_peer_allow_to_unconfined(self):
        '''Test confined peer allow to unconfined'''
        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(peer_label='unconfined')
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_be_confined_bad_peer_to_unconfined(self):
        '''Test confined bad peer to unconfined'''
        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(peer_label='unconfinedXXX')
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_ca_confined_deny_to_unconfined(self):
        '''Test confined deny to unconfined'''
        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(allow_send=False)
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_cb_confined_deny_to_confined_allow(self):
        '''Test confined deny to confined allow'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol()
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(allow_send=False)
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_cc_confined_deny_to_confined_deny(self):
        '''Test confined deny to confined deny'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(allow_receive=False)
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(allow_send=False)
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_da_audit_works(self):
        '''Test audit works'''
        extra_pol = "audit dbus,"

        pol = os.path.join(self.tmpdir, "server.pol")
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        self._gen_policy(self.client, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_async_client()
        self._run_client_exit()

    def test_db_deny_server_works(self):
        '''Test deny works for the server'''
        pol = os.path.join(self.tmpdir, "server.pol")
        self._gen_policy(self.server, pol, "deny dbus,")

        pol = os.path.join(self.tmpdir, "client.pol")
        self._gen_policy(self.client, pol, "")

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, "")

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_dc_deny_client_works(self):
        '''Test deny works for the client'''
        pol = os.path.join(self.tmpdir, "server.pol")
        self._gen_policy(self.server, pol, "")

        pol = os.path.join(self.tmpdir, "client.pol")
        self._gen_policy(self.client, pol, "deny dbus,")

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, "deny dbus,")

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_dd_audit_deny_server_works(self):
        '''Test audit deny works for the server'''
        pol = os.path.join(self.tmpdir, "server.pol")
        self._gen_policy(self.server, pol, "audit deny dbus,")

        pol = os.path.join(self.tmpdir, "client.pol")
        self._gen_policy(self.client, pol, "")

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, "")

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_de_audit_deny_client_works(self):
        '''Test audit deny works for the client'''
        pol = os.path.join(self.tmpdir, "server.pol")
        self._gen_policy(self.server, pol, "")

        pol = os.path.join(self.tmpdir, "client.pol")
        self._gen_policy(self.client, pol, "audit deny dbus,")

        pol = os.path.join(self.tmpdir, "async_client.pol")
        self._gen_policy(self.async_client, pol, "audit deny dbus,")

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_async_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_ea_unconfined_eavesdropping(self):
        '''Test unconfined eavesdropping'''
        rc, report = testlib.cmd([os.path.join(os.getcwd(), "dbus/simple-eavesdrop-addmatch.py")])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_eb_not_allowed_eavesdropping(self):
        '''Test confined, not allowed eavesdropping'''
        simple_eavesdrop = os.path.join(os.getcwd(), "dbus/simple-eavesdrop-addmatch.py")
        pol = os.path.join(self.tmpdir, "eavesdrop.pol")
        self._gen_policy(simple_eavesdrop, pol, "")

        rc, report = testlib.cmd([simple_eavesdrop])
        expected = self.deny_expected
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_ec_allowed_eavesdropping(self):
        '''Test confined, allowed eavesdropping'''
        simple_eavesdrop = os.path.join(os.getcwd(), "dbus/simple-eavesdrop-addmatch.py")
        pol = os.path.join(self.tmpdir, "eavesdrop.pol")

        rule = "dbus eavesdrop,"
        expected = 0
        if self.lsb_release['Release'] < 14.04:
            # In 13.10, confined applications could not eavesdrop. In 14.04,
            # AppArmor gained support for the eavesdrop permission.
            rule = "dbus,"
            expected = self.deny_expected
        self._gen_policy(simple_eavesdrop, pol, rule)

        rc, report = testlib.cmd([simple_eavesdrop])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_ed_audited_eavesdropping(self):
        '''Test confined, audited eavesdropping'''
        simple_eavesdrop = os.path.join(os.getcwd(), "dbus/simple-eavesdrop-addmatch.py")
        pol = os.path.join(self.tmpdir, "eavesdrop.pol")

        rule = "audit dbus eavesdrop,"
        expected = 0
        if self.lsb_release['Release'] < 14.04:
            # In 13.10, confined applications could not eavesdrop. In 14.04,
            # AppArmor gained support for the eavesdrop permission.
            rule = "audit dbus,"
            expected = self.deny_expected
        self._gen_policy(simple_eavesdrop, pol, rule)

        rc, report = testlib.cmd([simple_eavesdrop])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_ee_denied_eavesdropping(self):
        '''Test confined, denied eavesdropping'''
        simple_eavesdrop = os.path.join(os.getcwd(), "dbus/simple-eavesdrop-addmatch.py")
        pol = os.path.join(self.tmpdir, "eavesdrop.pol")

        rule = "deny dbus eavesdrop,"
        expected = 1
        if self.lsb_release['Release'] < 14.04:
            # In 13.10, confined applications could not eavesdrop. In 14.04,
            # AppArmor gained support for the eavesdrop permission.
            rule = "deny dbus,"
        self._gen_policy(simple_eavesdrop, pol, rule)

        rc, report = testlib.cmd([simple_eavesdrop])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_fa_confined_deny_to_confined_allow_peer_labels(self):
        '''Test confined deny to confined allow w/ peer labels'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(peer_label=self.client)
        self._gen_policy(self.server, pol, extra_pol)

        # Create a client policy with a bad peer label
        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(peer_label=(self.client + 'XXX'))
        self._gen_policy(self.client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_fb_confined_allow_to_confined_deny_peer_labels(self):
        '''Test confined allow to confined deny w/ peer labels'''
        # Create a server policy with a bad peer label
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(peer_label=(self.client + 'XXX'))
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(peer_label=self.client)
        self._gen_policy(self.client, pol, extra_pol)

        self._run_server()
        self._run_client(expected=self.deny_expected)
        self._run_client_exit(expected=self.deny_expected)

    def test_fc_confined_allow_to_confined_allow_peer_labels(self):
        '''Test confined allow to confined allow w/ peer labels'''
        pol = os.path.join(self.tmpdir, "server.pol")
        extra_pol = self._extra_server_pol(peer_label=self.client)
        self._gen_policy(self.server, pol, extra_pol)

        pol = os.path.join(self.tmpdir, "client.pol")
        extra_pol = self._extra_client_pol(peer_label=self.server)
        self._gen_policy(self.client, pol, extra_pol)

        self._run_server()
        self._run_client()
        self._run_client_exit()

    def _test_zz_private_buses_work(self):
        '''TODO: Test private buses work'''

class DBusAppArmorSystem(DBusAppArmorCommon):
    '''Tests for AppArmor with DBus system'''
    def setUp(self):
        '''Generic test setup'''
        DBusAppArmorCommon._setUp(self, bus="system")

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()

class DBusAppArmorSession(DBusAppArmorCommon):
    '''Tests for AppArmor with DBus session'''
    def setUp(self):
        '''Generic test setup'''
        DBusAppArmorCommon._setUp(self, bus="session")

    def tearDown(self):
        '''Tear down method'''
        self._tearDown()


if __name__ == '__main__':
    listener = DBusListener()
    atexit.register(listener.stop)

    ubuntu_version = testlib.manager.lsb_release["Release"]

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DBusTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DBusTestPlan))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DBusBindings))

    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DBusPrivateTest))

    # these should be after all the other tests, cause they may abort
    if ubuntu_version >= 13.10:
	# These tests *must* be run in this order as restarting dbus is
        # problematic
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DBusAppArmorSession))
        print >>sys.stderr, "TODO: Implement system bus tests"
        # suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DBusAppArmorSystem))
    else:
        print >>sys.stderr, "Skipping AppArmor/DBus regression tests on 13.04 and lower"

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

    print >>sys.stderr, "TODO: check that dbus-daemon is confined in _apparmor_enabled()"
