#!/usr/bin/python
#
#    test-krb5.py quality assurance test script
#    Copyright (C) 2008-2015 Canonical Ltd.
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

    *** THIS TEST DESTROYS EXISTING krb5 DATABASES ***

    Note: DNS forward/reverse must be sane for the machines using krb5

    How to run against a clean schroot named 'gutsy':
        schroot -c gutsy -u root -- sh -c 'apt-get -y install python-pexpect krb5-admin-server krb5-kdc krb5-config krb5-user krb5-clients && ./test-krb5.py -v'

    If libpam-krb5 is installed, it will also test it.
    Note: This is disabled for now as libpam-krb5 doesn't seem to work on the same host as the kerberos server
          Getting this error message: preauth (timestamp) verify failure: Decrypt integrity check failed

    Setup is based on instructions at:
    http://www.alittletooquiet.net/text/kerberos-on-ubuntu/

    TODO: Split into server/client components for client tests and pam module

'''
# QRT-Packages: python-pexpect krb5-admin-server krb5-kdc krb5-config krb5-user krb5-clients haveged
# QRT-Privilege: root

import unittest, subprocess, time, socket, glob, os, pexpect
import testlib

class KerberosSettings(object):
    def __init__(self):
        self.admin_password = None
        self.user_password = None
        self.user = None

    def setup(self):
        self.admin_password = testlib.random_string(12)
        self.user = testlib.TestUser(lower=True)
        # have a separate kerberos password from login password for user
        self.user_password = testlib.random_string(12)

    def teardown(self):
        krb5.user = None

krb5 = KerberosSettings()

class KerberosTest(testlib.TestlibCase):
    '''Test Kerberos behaviors.'''

    def setUp(self):
        '''Set up for each krb5 test'''
        self.fqdn = socket.getfqdn()
        self.hostname = socket.gethostname()
        self.domainname = ".".join(self.fqdn.split('.')[1:])
        # Need "real" DNS...
        # Make sure the hostname is not in 127.0.0.1 in /etc/hosts
        self.assertFalse(self.domainname == 'localdomain')
        self.assertFalse(self.hostname == 'localhost')
        # Make sure that the domain is set to something
        self.assertFalse(self.domainname == '')
        # Presently, we test against the local system, so the client
        # is the server...
        self.fqdn_client = self.fqdn

        self.pam_auth = "/etc/pam.d/common-auth"
        self.pam_krb5 = "/lib/security/pam_krb5.so"

    def onetime_setUp(self):
        '''Set up prior to test_* functions'''

        # Set up configuration based on system name/domain
        config = '''#
[libdefaults]
default_realm = LOCAL.NETWORK

# Here, we specify the kdc and admin server for the realm
# LOCAL.NETWORK
[realms]
LOCAL.NETWORK = {
  kdc = %s
  admin_server = %s
}

# This informs the kdc of which hosts it should consider part of the
# LOCAL.NETWORK realm
[domain_realm]
%s = LOCAL.NETWORK
.%s = LOCAL.NETWORK
''' % (self.fqdn, self.fqdn, self.domainname, self.domainname)

        if self.lsb_release['Release'] < 9.10:
            config += '''
# I disable kerberos 4 compatibility altogether.  I understand it had
# some real security issues.  I don't know if this is important here,
# but, it doesn't hurt in my particular case (all clients on my network
# are kerberos 5 compatible).
[login]
krb4_convert = true
krb4_get_tickets = true
'''
        testlib.config_replace('/etc/krb5.conf',config)

        testlib.config_replace('/etc/krb5kdc/kdc.conf','''#
[kdcdefaults]
    kdc_ports = 750,88

[realms]
    LOCAL.NETWORK = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = FILE:/etc/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        kdc_ports = 750,88
        max_life = 10h 0m 0s
        max_renewable_life = 7d 0h 0m 0s
        master_key_type = des3-hmac-sha1
        supported_enctypes = des3-hmac-sha1:normal des-cbc-crc:normal des:normal des:v4 des:norealm des:onlyrealm des:afs3
        default_principal_flags = +preauth
    }
''')

        # destroy old principals
        for drop in glob.glob('/etc/krb5kdc/principal*') + glob.glob('/var/lib/krb5kdc/principal*'):
            os.unlink(drop)

        # Generate principals for initial database
        krb5.setup()
        self.assertFalse(krb5.user_password == krb5.user.password,"need different passwords between login and krb5")

        handle, name = testlib.mkstemp_fill('%s\n%s\n' % (krb5.admin_password, krb5.admin_password))
        rc, out = testlib.cmd(['/usr/sbin/kdb5_util','create','-s'], stdin=handle)
        os.unlink(name)
        self.assertEquals(rc,0,"krb database initialization: "+out)

        handle, name = testlib.mkstemp_fill('%s\n' % (krb5.admin_password))
        rc, out = testlib.cmd(['/usr/sbin/kadmin.local','-q','addprinc admin/admin'], stdin=handle)
        os.unlink(name)
        self.assertEquals(rc,0,"krb admin add: "+out)

        handle, name = testlib.mkstemp_fill('%s\n%s\n' % (krb5.user_password, krb5.user_password))
        rc, out = testlib.cmd(['/usr/sbin/kadmin.local','-p','admin/admin','-q','addprinc %s' % (krb5.user.login)], stdin=handle)
        os.unlink(name)
        self.assertEquals(rc,0,"krb user add: "+out)
        self.assertTrue('Principal "%s@LOCAL.NETWORK" created.' % (krb5.user.login) in out,"kadmin.local failure: "+out);

        handle, name = testlib.mkstemp_fill('''addprinc -randkey host/%s
addprinc -randkey host/%s
ktadd host/%s
quit
''' % (self.fqdn, self.fqdn_client, self.fqdn))
        rc, out = testlib.cmd(['/usr/sbin/kadmin.local','-p','admin/admin'], stdin=handle)
        os.unlink(name)
        self.assertEquals(rc,0,"krb user/host principals not added: "+out)


        k5login = '%s/.k5login' % (krb5.user.home)
        file(k5login,'w').write('%s@LOCAL.NETWORK\n' % (krb5.user.login))
        os.chown(k5login, krb5.user.uid, krb5.user.gid)

        # restart
        self._restart_services()

        # Is libpam-krb5 installed?
        #if (os.path.isfile(self.pam_krb5)):
        #    self.pam_krb5_setUp()

    def pam_krb5_setUp(self):
        '''Set up pam with libpam-krb5'''

        # Jaunty now has pam-auth-update
        if self.lsb_release['Release'] < 9.04:
            testlib.config_replace(self.pam_auth,"",True)
            # add to the beginning of the pam file.
            subprocess.call(['sed', '-i', '1iauth	sufficient	pam_krb5.so', self.pam_auth])
            #subprocess.call(['sed', '-i', 's/required/sufficient/', self.pam_auth])

    def pam_krb5_tearDown(self):
        '''Restore pam configuration'''

        # Jaunty now has pam-auth-update
        if self.lsb_release['Release'] < 9.04:
            testlib.config_restore(self.pam_auth)

    def _restart_services(self,off=False):
        for initscript in ['krb5-kdc','krb5-admin-server']:
            subprocess.call(['/etc/init.d/%s' % (initscript), 'stop'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if not off:
                self.assertTrue(subprocess.call(['/etc/init.d/%s' % (initscript), 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0)

    def onetime_tearDown(self):
        '''Clean up after test_* functions'''
        testlib.config_restore('/etc/krb5.conf')
        testlib.config_restore('/etc/krb5kdc/kdc.conf')
        self._restart_services(off=True)
        krb5.teardown()

        # Is libpam-krb5 installed?
        #if (os.path.isfile(self.pam_krb5)):
        #    self.pam_krb5_tearDown()

    def test_00_initialize(self):
        '''Set up initial configuration'''
        self.onetime_setUp()

    def _kinit(self,login,password,v4=False):
        '''Attempt kinit for a given user and password'''
        handle, name = testlib.mkstemp_fill("%s\n" % (password))
        if v4:
            v4str="-5 -4"
        else:
            v4str=""
        rc, out = testlib.cmd(['/bin/su','-c','/usr/bin/kinit -V %s %s' % (v4str, login), login], stdin=handle)
        os.unlink(name)
        return rc, out

    def _destroy_tickets(self,v4=False):

        if self.lsb_release['Release'] <= 14.04:
            not_found = 'No credentials cache found'
        else:
            not_found = 'not found'

        rc, out = testlib.cmd(['/bin/su','-c','/usr/bin/kdestroy', krb5.user.login])
        if (rc != 0):
            self.assertTrue(not_found in out,'kdestroy: '+out)

        rc, out = self._check_klist(v4)
        self.assertTrue(rc == 1,"klist rc(%d) != 1: %s" % (rc,out))
        self.assertTrue(not_found in out, "klist has cache: "+out)

    def test_10_kinit(self):
        '''User can initialize via krb5'''
        v4=False
        if self.lsb_release['Release'] < 9.10:
            v4=True
        self._destroy_tickets(v4)

        rc, out = self._kinit(krb5.user.login, krb5.user.password)
        self.assertFalse(rc == 0,"krb5 kinit with bad password: "+out)

        rc, out = self._kinit(krb5.user.login, krb5.user_password)
        self.assertTrue(rc == 0,"krb5 kinit with good password: "+out)

    def _check_klist(self, v4=False):
        if v4:
            vstr="-5 -4"
        else:
            vstr="-5"
        handle, name = testlib.mkstemp_fill("%s\n" % (krb5.user_password))
        rc, out = testlib.cmd(['/bin/su','-c','/usr/bin/klist %s' % (vstr), krb5.user.login], stdin=handle)
        os.unlink(name)
        return rc, out

    def test_klist_00(self):
        '''Ticket cache empty after v5 init'''
        v4=False
        expected=0
        if self.lsb_release['Release'] < 9.10:
            v4=True
            expected=1
        rc, out = self._check_klist(v4)

        self.assertTrue(rc == expected,"klist rc(%d) != %d: %s" % (rc,expected,out))
        self.assertTrue('Default principal: %s@LOCAL.NETWORK' % (krb5.user.login) in out, "klist missing Default principal: "+out)
        self.assertFalse('Principal: %s@LOCAL.NETWORK' % (krb5.user.login) in out, "klist has v4 principal: "+out)
        self.assertTrue('krbtgt/LOCAL.NETWORK@LOCAL.NETWORK' in out, "klist missing v5 ticket: "+out)
        self.assertTrue('renew until ' in out, "klist missing renewal: "+out)

    def test_klist_10_v4(self):
        '''Ticket cache exists after v4 init'''
        if self.lsb_release['Release'] > 9.04:
            self._skipped("v4 no longer supported")
            return

        rc, out = self._kinit(krb5.user.login, krb5.user_password, v4=True)
        self.assertTrue(rc == 0,"krb5 v4 kinit with good password: "+out)

        rc, out = self._check_klist(v4=True)
        #print rc, out
        self.assertTrue(rc == 0,"klist rc(%d) != 0: %s" % (rc,out))
        self.assertTrue('Default principal: %s@LOCAL.NETWORK' % (krb5.user.login) in out, "klist missing Default principal: "+out)
        self.assertTrue('Principal: %s@LOCAL.NETWORK' % (krb5.user.login) in out, "klist missing v4 principal: "+out)
        self.assertTrue('renew until ' in out, "klist missing renewal: "+out)
        self.assertTrue('krbtgt/LOCAL.NETWORK@LOCAL.NETWORK' in out, "klist missing v5 ticket: "+out)
        self.assertTrue('krbtgt.LOCAL.NETWORK@LOCAL.NETWORK' in out, "klist missing v4 ticket: "+out)

    def test_pam_login(self):
        '''Test pam login'''

        # This is disabled for now
        self._skipped("Disabled for now")
        return True

        if not (os.path.isfile(self.pam_krb5)):
            self._skipped("libpam-krb5 is not installed")
            return True

        print krb5.user.login, krb5.user.password, krb5.user_password, krb5.admin_password
        subprocess.call(['bash'])

        child = pexpect.spawn('login')
        time.sleep(0.2)
        child.expect('.* (?i)login: ', timeout=5)
        time.sleep(0.2)
        child.sendline(krb5.user.login)
        time.sleep(0.2)
        child.expect('(?i)password: ', timeout=5)
        time.sleep(0.2)
        rc = child.sendline(krb5.user_password)
        time.sleep(0.2)
        try:
            i = child.expect('.*\$', timeout=5)
            time.sleep(0.2)
            child.sendline('exit')
        except:
            expected = 9
            self.assertEquals(rc, expected, "login returned %d" %(rc))

        time.sleep(0.2)
        child.kill(0)

    def test_za_destroy(self):
        '''Verify ticket release'''
        v4=False
        if self.lsb_release['Release'] < 9.10:
            v4=True
        self._destroy_tickets(v4)

    def test_zz_cleanup(self):
        '''Clean up configurations'''
        #print krb5.user.login, krb5.user.password, krb5.user_password, krb5.admin_password
        self.onetime_tearDown()

if __name__ == '__main__':
    unittest.main()
