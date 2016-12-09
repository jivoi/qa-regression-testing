#!/usr/bin/python
#
#    test-dnsmasq.py quality assurance test script
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Copyright (C) 2008-2016 Canonical Ltd.
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
    In a virtual machine:
    sudo apt-get -y install python-adns dnsmasq dnsutils && ./test-dnsmasq.py -v'

    For this script to successfully run, the Network Manager dnsmasq integration
    needs to be disabled in the VM by commenting out the "dns=dnsmasq" line from
    /etc/NetworkManager/NetworkManager.conf.

    TODO:
        DHCP integration
        killall -10 dnsmasq testing
        SRV lookups
'''

# QRT-Depends: testlib_dns.py
# QRT-Packages: python-adns dnsmasq dnsutils tftp-hpa

import unittest, subprocess, os, sys
import adns
import tempfile
import testlib
import testlib_dns

class DnsmasqCommon(testlib_dns.DnsCommon):
    '''Common server routines'''
    def _setUp(self):
        '''Setup mechanisms'''
        self.tmpdir = ""
        self._set_initscript("/etc/init.d/dnsmasq")
        self.daemon.stop()
        self.config = "/etc/dnsmasq.conf"
        self.rundir = "/var/run/dnsmasq"

    def _tearDown(self):
        '''Shutdown methods'''
        testlib.config_restore(self.config)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)
        testlib_dns.DnsCommon._tearDown(self)

    def _testDaemons(self, daemons):
        '''Daemons running'''
        for d in self.daemons:
            pidfile = os.path.join(self.rundir, d + ".pid")
            warning = "Could not find pidfile '" + pidfile + "'"
            self.assertTrue(os.path.exists(pidfile), warning)
            self.assertTrue(testlib.check_pidfile(d, pidfile))

    def _test_port(self, port, proto="udp"):
        '''Test port'''
        self.daemon.stop()
        self.assertFalse(testlib.check_port(port, proto))
        self.daemon.start()
        self.assertTrue(testlib.check_port(port, proto))

class DnsmasqGeneric(DnsmasqCommon):
    '''Test dnsmasq server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        DnsmasqCommon._setUp(self)
        self.daemon.start()

    def tearDown(self):
        '''Shutdown methods'''
        DnsmasqCommon._tearDown(self)

    def test_daemons(self):
        '''Daemons running'''
        self.assertTrue(self.daemon.status(), "Status failed")

        self.daemons = [ "dnsmasq" ]
        DnsmasqCommon._testDaemons(self, self.daemons)

class DnsmasqDNS(DnsmasqCommon):
    '''Test dnsmasq DNS server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        DnsmasqCommon._setUp(self)

        self.dns = adns.init(adns.iflags.noautosys,sys.stderr,'nameserver 127.0.0.1')

        # Allow for opendns on the network...
        testlib.config_replace(self.config, "", True)
        subprocess.call(['sed', '-i', 's,^#bogus-nxdomain=.*,bogus-nxdomain=' + testlib.bogus_nxdomain + ',g', self.config])

        self.daemon.start()

    def tearDown(self):
        '''Shutdown methods'''
        DnsmasqCommon._tearDown(self)

    def test_external_lookups(self):
	'''Test external lookups via the server'''
        self._test_external_lookups()

    def test_internal_lookups(self):
	'''Test internal lookups via the server'''
        self.query('localhost.', 'A', '127.0.0.1')
        self.query('1.0.0.127.in-addr.arpa', 'PTR', 'localhost')

    def test_domain_port(self):
        '''Test domain port'''
        DnsmasqCommon._test_port(self, 53)

class DnsmasqDHCP(DnsmasqCommon):
    '''Test dnsmasq DHCP server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        DnsmasqCommon._setUp(self)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        testlib.config_replace(self.config, "\ndhcp-range=192.168.0.128,192.168.0.164,255.255.255.0,12h\n", True)

        self.daemon.start()

    def tearDown(self):
        '''Shutdown methods'''
        DnsmasqCommon._tearDown(self)

    def test_dhcp_port(self):
        '''Test dhcp port'''
        DnsmasqCommon._test_port(self, 67)

class DnsmasqTFTP(DnsmasqCommon):
    '''Test dnsmasq DNS server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        DnsmasqCommon._setUp(self)
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        subprocess.call(['chown', 'dnsmasq', self.tmpdir])

        testlib.config_replace(self.config, "", True)
        subprocess.call(['sed', '-i', 's,^#enable-tftp,enable-tftp,g', self.config])
        subprocess.call(['sed', '-i', 's,^#tftp-root=.*,tftp-root=' + self.tmpdir + ',g', self.config])

        self.daemon.start()

    def tearDown(self):
        '''Shutdown methods'''
        DnsmasqCommon._tearDown(self)

    def test_tftp_port(self):
        '''Test tftp port'''

        DnsmasqCommon._test_port(self, 69)

    def test_tftp(self):
        '''Test basic tftp'''

        contents = "success\n"
        fn = os.path.join(self.tmpdir, "dtest.txt")
        dfn = fn + ".dl"
        testlib.create_fill(fn, contents)

        args = ['tftp', '-m', 'binary', '127.0.0.1', '-c', 'get', '%s' % os.path.basename(fn), '%s' % dfn]
        rc, report = testlib.cmd(args)
        self.assertTrue(os.path.exists(dfn), "'%s' does not exist" % dfn)
        self.assertTrue("success" in file(dfn).read(), "'success' not found in '%s'" % dfn)

        contents = "success\n"
        fn = os.path.join(self.tmpdir, "utest.txt")
        ufn = fn + ".ul"
        testlib.create_fill(ufn, contents)

        # dnsmasq does not support PUT, make sure of that
        args = ['tftp', '-m', 'binary', '127.0.0.1', '-c', 'put', '%s' % ufn, '%s' % os.path.basename(fn)]
        rc, report = testlib.cmd(args)
        self.assertFalse(os.path.exists(fn), "'%s' does not exist" % fn)

    def test_tftp_secure(self):
        '''Test secure tftp'''

        self.daemon.stop()
        subprocess.call(['sed', '-i', 's,^#tftp-secure,tftp-secure,g', self.config])
        self.daemon.start()

        fn = os.path.join(self.tmpdir, "test.txt")
        testlib.create_fill(fn, "stuff\n")

        subprocess.call(['chmod', '640', fn])
        subprocess.call(['chown', 'root', fn])
        dfn = fn + '.root'
        args = ['tftp', '-m', 'binary', '127.0.0.1', '-c', 'get', '%s' % os.path.basename(fn), '%s' % dfn]
        rc, report = testlib.cmd(args)
        # tftp-hpa will create a zero length file on error, so need to check the contents
        # if the file exists
        if os.path.exists(dfn):
            self.assertFalse("stuff" in file(dfn).read(), "'stuff' found in '%s'" % dfn)

        subprocess.call(['chown', 'dnsmasq', fn])
        dfn = fn + '.dnsmasq'
        args = ['tftp', '-m', 'binary', '127.0.0.1', '-c', 'get', '%s' % os.path.basename(fn), '%s' % dfn]
        rc, report = testlib.cmd(args)
        self.assertTrue(os.path.exists(dfn), "'%s' does not exist" % dfn)
        self.assertTrue("stuff" in file(dfn).read(), "'stuff' not found in '%s'" % dfn)


if __name__ == '__main__':

    # Test if NetworkManager is running dnsmasq
    rc, report = testlib.cmd(['ps', 'ax'])
    if 'org.freedesktop.NetworkManager.dnsmasq' in report:
        print >>sys.stderr, ("\n\nMust not be running dnsmasq! Please comment out dnsmasq integration in")
        print >>sys.stderr, ("/etc/NetworkManager/NetworkManager.conf and reboot!\n\n")
        sys.exit(1)

    suite = unittest.TestSuite()

    # add tests here
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DnsmasqGeneric))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DnsmasqDNS))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DnsmasqDHCP))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(DnsmasqTFTP))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
