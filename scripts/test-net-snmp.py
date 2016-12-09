#!/usr/bin/python
#
#    test-net-snmp.py quality assurance test script for net-snmp
#    Copyright (C) 2008-2012 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install snmpd snmp python-pysnmp4 libnet-snmp-perl netbase && ./test-net-snmp.py -v'

    To run on Dapper, you will need to test from another host/chroot.
    Run this script normally on Dapper and it will configure the SNMP daemon,
    then run "test-net-snmp HOSTNAME -v" on the other host, pointing to the
    Dapper SNMP daemon host.  (HOSTNAME can be "localhost" if you want to
    run the test from a local chroot.)
'''
# QRT-Packages: snmpd snmp python-pysnmp4 libnet-snmp-perl netbase
# QRT-Alternates: snmp-mibs-downloader snmpd
# QRT-Depends: net-snmp

import unittest, subprocess, sys, shutil, tempfile, glob, os
import testlib

class NetSnmpConfig(object):
    '''Sets up configurations for SNMP daemon'''

    def __init__(self):
        try:
            from pysnmp.smi import builder, view
            self.mibBuilder = builder.MibBuilder().loadModules('SNMPv2-MIB')
            #self.mibViewController = view.MibViewController(self.mibBuilder)
        except:
            # Allow Dapper to fail
            pass

        # Config details
        self.info = dict()
        self.info.setdefault('sysLocation','Testbed')
        self.info.setdefault('sysContact','QA Department')

        # Config files
        self.default_snmp = "/etc/default/snmpd"
        self.snmp_conf = "/etc/snmp/snmp.conf"

        # Remote testing support
        self.remote_daemon = False

    def start(self):
        '''Configure the SNMP daemon'''
        if self.remote_daemon:
            return 0, "Skipped: remote daemon"
        self.stop()

        info_config = ""
        for key in self.info.keys():
            info_config += "%s %s\n" % (key, self.info[key])
        testlib.config_replace('/etc/snmp/snmpd.local.conf','''#
# sys* values
%s

# Create some v3 users
createUser authperson  SHA  authpassphrasehere
createUser noauthperson SHA anotherphrasehere
createUser allperson  SHA  allpassphrasehere
createUser md5person  MD5  md5passphrasehere

# Configure what they can see
rouser authperson auth sysUptime
rouser noauthperson noauth sysLocation
rouser allperson auth 1.3
rouser md5person auth sysUptime

''' % info_config)

        # Natty and higher doesn't ship with MIBs by default
        # so we need to re-enable them.
        if testlib.manager.lsb_release["Release"] >= 11.04:
            testlib.config_replace(self.default_snmp, "", True)
            subprocess.call(['sed', '-i', 's/^export MIBS/#export MIBS/', self.default_snmp])
            testlib.config_replace(self.snmp_conf, "", True)
            subprocess.call(['sed', '-i', 's/^mibs/#mibs/', self.snmp_conf])

        return testlib.cmd(['/etc/init.d/snmpd','start'])


    def stop(self):
        '''stop the SNMP daemon'''
        if self.remote_daemon:
            return 0, "Skipped: remote daemon"
        rc, out = testlib.cmd(['/etc/init.d/snmpd','stop'])
        #testlib.config_restore('/etc/snmp/snmpd.local.conf')

        if testlib.manager.lsb_release["Release"] >= 11.04:
            testlib.config_restore(self.default_snmp)
            testlib.config_restore(self.snmp_conf)

        return rc, out

    def node(self, *items):
        mibNode, = self.mibBuilder.importSymbols(*items)
        return mibNode

    def set_remote_daemon(self, value):
        self.remote_daemon = value

snmpd = NetSnmpConfig()

try:
    from pysnmp.entity.rfc3413.oneliner import cmdgen
except:
    print >>sys.stderr, "Dapper lacks the required SNMP python libraries."
    snmpd.stop()
    snmpd.start()
    print >>sys.stderr, "A test configuration for the SNMP daemon has loaded."
    print >>sys.stderr, "Please test this daemon from another host."
    sys.exit(1)

test_host = 'localhost'
if len(sys.argv)>1 and sys.argv[1] != '-v':
    test_host = sys.argv.pop(1)
    snmpd.set_remote_daemon(True)
    print >>sys.stderr, "Performing remote daemon tests on %s" % (test_host)

class NetSnmpTest(testlib.TestlibCase):
    '''Test net-snmp.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.snmpd = snmpd
        self.fs_dir = os.path.abspath('.')

        self.evil_hmac_client = '%s/net-snmp/evil-hmac-snmpget.%s.%s' % (self.fs_dir, self.lsb_release['Codename'],self.dpkg_arch)

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)

    def _query(self, oid,
               user=None, authkey=None, privkey=None,
               authproto=None, privproto=None,
               error=None, status=0):
        '''Perform SNMP query'''

        authinfo = cmdgen.CommunityData('test-agent', 'public', 0)
        if user:
            authinfo = cmdgen.UsmUserData(user, authkey, privkey, authproto, privproto)

        errorIndication, errorStatus, errorIndex, varBinds = cmdgen.CommandGenerator().getCmd(
            authinfo,
            cmdgen.UdpTransportTarget((test_host, 161)),
            oid)
        # Test for errors
        self.assertEquals(errorIndication, error, errorIndication)
        if error == None:
            self.assertEquals(errorStatus, status, errorStatus)
            # Validate that we got the oid we asked for
            self.assertEquals(oid, varBinds[0][0], varBinds)
        return varBinds

    def test_00_setup(self):
        '''Configure and start SNMP daemon'''

        rc, out = self.snmpd.start()
        self.assertEquals(rc, 0, out)

    def _bogus_query(self):
        '''Verify that a listening instance is rejecting bad queries'''
        # Verify negative values
        self.assertShellExitEquals(2, ['snmpget','-v1','-cpublic',test_host,'sysLocation.1'])

    def _valid_query(self):
        '''Verify that a listening instance is responding to good queries'''
        # Verify positive values
        self.assertShellExitEquals(0, ['snmpget','-v1','-cpublic',test_host,'sysLocation.0'])

    def test_10_config_v1(self):
        '''SNMP v1 Configuration'''

        # Verify the hardcoded configuration
        for key in self.snmpd.info.keys():
            result = self._query(self.snmpd.node('SNMPv2-MIB',key).getName()+(0,))
            self.assertEquals(self.snmpd.info[key], result[0][1], result)
            self.assertShellExitEquals(0, ['snmpget','-v1','-cpublic',test_host,'%s.0' % (key)])

        self._valid_query()
        self._bogus_query()

    def test_20_config_v3(self):
        '''SNMP v3 Configuration'''

        # Fetch public value to verify against
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysUpTime').getName()+(0,))
        uptime = result[0][1]

        # authperson can see sysUpTime
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysUpTime').getName()+(0,), user='authperson', authkey='authpassphrasehere', authproto=cmdgen.usmHMACSHAAuthProtocol)
        self.assertTrue(result[0][1] >= uptime, result)
        # noauthperson can not see sysUpTime
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysUpTime').getName()+(0,), user='noauthperson')
        self.assertEquals(result[0][1],'',result)

        # authperson can not see sysLocation
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysLocation').getName()+(0,), user='authperson', authkey='authpassphrasehere', authproto=cmdgen.usmHMACSHAAuthProtocol)
        self.assertEquals(result[0][1],'',result)
        # noauthperson can see sysLocation
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysLocation').getName()+(0,), user='noauthperson')
        self.assertEquals(result[0][1],self.snmpd.info['sysLocation'],result)

        # Test login failures
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysLocation').getName()+(0,), user='authperson', authkey='bad password', authproto=cmdgen.usmHMACSHAAuthProtocol, error='wrongDigest')
        result = self._query(self.snmpd.node('SNMPv2-MIB','sysLocation').getName()+(0,), user='noauthperson', authkey='bad password', authproto=cmdgen.usmHMACSHAAuthProtocol, error='wrongDigest')


    def disabled_test_70_HMAC_patched_client(self):
        '''Build patched HMAC-spoofing client'''
        # This is for an ancient CVE and takes forever to build, disable
        # for now.

        if not os.path.exists(self.evil_hmac_client):
            self.install_packages(['build-essential','fakeroot','patch'])
            self.install_builddeps('net-snmp')
            tempdir = tempfile.mkdtemp()
            self.assertNotEquals(None, tempdir)
            os.chdir(tempdir)
            self.assertShellExitEquals(0,['apt-get','source','net-snmp'])
            os.chdir(glob.glob('net-snmp-*')[0])
            self.assertShellExitEquals(0,['patch','-p0','snmplib/snmpusm.c',self.fs_dir + '/net-snmp/CVE-2008-0960.patch'])
            self.assertShellExitEquals(0,['fakeroot','debian/rules','clean'])
            self.assertShellExitEquals(0,['fakeroot','debian/rules','binary'])
            # Force a static compile against the patched libraries
            os.chdir('apps')
            os.unlink('snmpget')
            os.environ.setdefault('LINKCC','')
            os.environ.setdefault('CC','')
            os.environ['LINKCC']='cc -static'
            os.environ['CC']='cc -static'
            self.assertShellExitEquals(0,['make','-e','snmpget'])
            shutil.copy2('snmpget', self.evil_hmac_client)
            os.chdir(self.fs_dir)
            shutil.rmtree(tempdir)

        # Test basic operation
        self.assertShellExitEquals(0,[self.evil_hmac_client,'-v1','-cpublic',test_host,'sysUpTime.0'])

    def disabled_test_71_HMAC_vulnerable(self):
        '''HMAC checks correct authentication string length (CVE-2008-0960)'''

        # Check valid auth
        self.assertShellExitEquals(0,[self.evil_hmac_client,'-v3','-u','md5person','-l','authNoPriv','-a','MD5','-A','md5passphrasehere',test_host,'sysUpTime.0'])
        # Check evil auth
        self.assertShellExitEquals(1, ['net-snmp/CVE-2008-0960.sh',self.evil_hmac_client,test_host,'md5person'])

    def test_80_bulk_works(self):
        '''Bulk Queries'''

        errorIndication, errorStatus, errorIndex, varTable = cmdgen.CommandGenerator().bulkCmd(
            cmdgen.UsmUserData('allperson', 'allpassphrasehere', None, cmdgen.usmHMACSHAAuthProtocol),
            cmdgen.UdpTransportTarget((test_host, 161)),
            0, 25, # nonRepeaters, maxRepetitions
            (1,3,6,1,2,1,1)
        )
        self.assertEquals(errorIndication, None, errorIndication)
        self.assertEquals(errorStatus, 0, errorStatus)

        def oid_matches(oid, text):
            for var in varTable:
                #print '0:', var[0][0]
                if oid == var[0][0]:
                    #print '1:', var[0][1]
                    self.assertTrue(text in str(var[0][1]), var)
                    return
            self.assertTrue(False, varTable)

        oid_matches((1,3,6,1,2,1,1,1,0), 'Linux')
        oid_matches((1,3,6,1,2,1,1,6,0), self.snmpd.info['sysLocation'])
        oid_matches((1,3,6,1,2,1,1,4,0), self.snmpd.info['sysContact'])

    def test_81_bulk_repetition_DoS(self):
        '''Bulk DoS (CVE-2008-4309)'''

        self.assertShellExitEquals(0, ['perl','net-snmp/CVE-2008-4309.pl',test_host])
        # Verify we're still running
        self._valid_query()
        self._bogus_query()

    def test_99_shutdown(self):
        '''SNMP daemon cleanup'''

        # Shut down
        rc, out = self.snmpd.stop()
        self.assertEquals(rc, 0, out)
        # Verify we stopped
        if not snmpd.remote_daemon:
            result = self._query((1,0),error='requestTimedOut')
            self.assertEquals(0, len(result), result)


if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
