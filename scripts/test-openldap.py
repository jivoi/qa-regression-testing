#!/usr/bin/python
#
#    test-openldap.py quality assurance test script
#    Copyright (C) 2008-2015 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.  THIS SCRIPT COULD DESTROY ALL SLAPD
  DATABASES
  *** IMPORTANT ***

  How to run:
    $ sudo apt-get -y install ldap-utils slapd db4.2-util \
      krb5-config krb5-user \
      libsasl2-modules-gssapi-mit (libsasl2-gssapi-mit on dapper and db4.7-util
      on jaunty)
    $ sudo ./test-openldap.py -v

  Debugging will be logged to /var/log/user.log

  NOTES:
    * when installing, just use the defaults
    * only run one instance of test-openldap.py at a time on the same machine

  KERBEROS/GSSAPI NOTES:
    * for testing kerberos/gssapi, need to have a working kerberos
      infrastructure (ideally on another machine). This assumes the 
      the default_realm to be EXAMPLE.COM and the domain_realm section to be
      set with:
      [domain_realm]
	.example.com = EXAMPLE.COM
	example.com = EXAMPLE.COM
    * the keytab file must contain a host principle, with the name
      'ldap/ldap.example.com' (if not using 'ldap.example.com', adjust
      ldap_fqdn in test_gssapi() and stored in /etc/krb5.keytab
    * ldap_fqdn (currently, 'ldap.example.com') must be resolvable via DNS,
      not resolve to the localhost, and reverse lookup must point back to
      ldap_fqdn
    * the ldapadmin@EXAMPLE.COM principle must exist in kerberos, and the user
      running this script must run 'kinit ldapadmin@EXAMPLE.COM'. Eg:
      $ sudo kinit ldapadmin@EXAMPLE.COM
      $ sudo ./test-openldap.py -v
    * the KDC and machine running this script must have the same time
    * the above was tested with MIT kerberos on hardy only

  TODO:
    - ipv6 testing (only does ipv4 now)
    - slurpd (look at ServerOverlays for possible implementation)
    - ldaps in sasl test_modules (TLS and client cert)
    - https://launchpad.net/bugs/249881 test case
    - add ldaps with client cert to test (now that we use gen_ssl() this
      shouldn't be too hard)
    - convert to cn=config for intrepid and later
    - https://help.ubuntu.com/10.04/serverguide/C/openldap-server.html for
      syncrepl and others
'''

# QRT-Depends: ssl testlib_ssl.py
# QRT-Packages: ldap-utils slapd krb5-config krb5-user libsasl2-modules-gssapi-mit openssl time fakeroot db5.1-util
# QRT-Alternates: db5.3-util
# QRT-Privilege: root
# QRT-Conflicts: libsasl2-modules-gssapi-heimdal

import unittest, subprocess, os, sys, tempfile, time, re, socket
import testlib
import testlib_ssl
import os.path

class ServerCommon(testlib.TestlibCase):
    '''Common server routines'''

    def _create_slapd_conf(self):
        '''Workaround until cn=config is supported in this script'''

        # this is taken from Ubuntu 8.04 LTS slapd
        conf = '''# This is the main slapd configuration file. See slapd.conf(5) for more
# info on the configuration options.

#######################################################################
# Global Directives:

# Features to permit
#allow bind_v2

# Schema and objectClass definitions
include         /etc/ldap/schema/core.schema
include         /etc/ldap/schema/cosine.schema
include         /etc/ldap/schema/nis.schema
include         /etc/ldap/schema/inetorgperson.schema
#EXTRA_INCLUDES

# Where the pid file is put. The init.d script
# will not stop the server if you change this.
pidfile         /var/run/slapd/slapd.pid

# List of arguments that were passed to the server
argsfile        /var/run/slapd/slapd.args

# Read slapd.conf(5) for possible values
loglevel        none

# Where the dynamically loaded modules are stored
modulepath      /usr/lib/ldap
moduleload      back_hdb
#EXTRA_MODULE_LOADS

# The maximum number of entries that is returned for a search operation
sizelimit 500

# The tool-threads parameter sets the actual amount of cpu's that is used
# for indexing.
tool-threads 1

#######################################################################
# Specific Backend Directives for hdb:
# Backend specific directives apply to this backend until another
# 'backend' directive occurs
backend         hdb

#######################################################################
# Specific Backend Directives for 'other':
# Backend specific directives apply to this backend until another
# 'backend' directive occurs
#backend                <other>

#######################################################################
# Specific Directives for database #1, of type hdb:
# Database specific directives apply to this databasse until another
# 'database' directive occurs
database        hdb

# The base of your directory in database #1
suffix          "dc=example,dc=com"

# rootdn directive for specifying a superuser on the database. This is needed
# for syncrepl.
# rootdn          "cn=admin,dc=example,dc=com"

# Where the database file are physically stored for database #1
directory       "/var/lib/ldap"

# The dbconfig settings are used to generate a DB_CONFIG file the first
# time slapd starts.  They do NOT override existing an existing DB_CONFIG
# file.  You should therefore change these settings in DB_CONFIG directly
# or remove DB_CONFIG and restart slapd for changes to take effect.

# For the Debian package we use 2MB as default but be sure to update this
# value if you have plenty of RAM
dbconfig set_cachesize 0 2097152 0

# Sven Hartge reported that he had to set this value incredibly high
# to get slapd running at all. See http://bugs.debian.org/303057 for more
# information.

# Number of objects that can be locked at the same time.
dbconfig set_lk_max_objects 1500
# Number of locks (both requested and granted)
dbconfig set_lk_max_locks 1500
# Number of lockers
dbconfig set_lk_max_lockers 1500

# Indexing options for database #1
index           objectClass eq

# Save the time that the entry gets modified, for database #1
lastmod         on

# Checkpoint the BerkeleyDB database periodically in case of system
# failure and to speed slapd shutdown.
checkpoint      512 30

# Where to store the replica logs for database #1
# replogfile    /var/lib/ldap/replog

# The userPassword by default can be changed
# by the entry owning it if they are authenticated.
# Others should not be able to see it, except the
# admin entry below
# These access lines apply to database #1 only
access to attrs=userPassword,shadowLastChange
        by dn="cn=admin,dc=example,dc=com" write
        by anonymous auth
        by self write
        by * none

# Ensure read access to the base for things like
# supportedSASLMechanisms.  Without this you may
# have problems with SASL not knowing what
# mechanisms are available and the like.
# Note that this is covered by the 'access to *'
# ACL below too but if you change that as people
# are wont to do you'll still need this if you
# want SASL (and possible other things) to work
# happily.
access to dn.base="" by * read

# The admin dn has full write access, everyone else
# can read everything.
access to *
        by dn="cn=admin,dc=example,dc=com" write
        by * read

# For Netscape Roaming support, each user gets a roaming
# profile for which they have write access to
#access to dn=".*,ou=Roaming,o=morsnet"
#        by dn="cn=admin,dc=example,dc=com" write
#        by dnattr=owner write

#######################################################################
# Specific Directives for database #2, of type 'other' (can be hdb too):
# Database specific directives apply to this databasse until another
# 'database' directive occurs
#database        <other>

# The base of your directory for database #2
#suffix         "dc=debian,dc=org"
'''

        handle, name = tempfile.mkstemp(prefix='slapd.conf',dir='/etc/ldap')
        handle = file(name,'w')
        handle.write(conf)
        handle.close()

        os.rename(name, self.config)
        subprocess.call(['chown', self.uid + ':' + self.gid, self.config])
        subprocess.call(['chmod', '0644', self.config])

    def _setUp(self,backend="bdb"):
        '''_setUp'''
        self.uid = "openldap"
        self.gid = "openldap"

        self.initscript = "/etc/init.d/slapd"

        # make sure the real slapd is not running
        subprocess.call([self.initscript, 'stop'], stdout=subprocess.PIPE)

        self.defaults = "/etc/default/slapd"
        self.rundir = "/var/run/slapd"
        self.config = "/etc/ldap/slapd.conf"
        self.datadir = "/var/lib/ldap"

        self._create_slapd_conf()

        # now back these up
        testlib.config_replace(self.defaults, "", True)
        testlib.config_replace(self.config, "", True)
        #testlib.config_replace(self.initscript, "", True)
        #subprocess.call(['chmod', '0755', self.initscript])

        assert os.path.isdir(self.datadir + ".autotest")
        if os.path.isdir(self.datadir):
            testlib.recursive_rm(self.datadir)
        subprocess.call(['cp', '-a', self.datadir + ".autotest", self.datadir])

        # set up defaults
        subprocess.call(['sed', '-i', 's,SLAPD_CONF=.*,SLAPD_CONF=\"' + self.config + '\",', self.defaults])
        #subprocess.call(['sed', '-i', 's,SLURPD_START=.*,SLURPD_START=yes,', self.defaults])
        subprocess.call(['sed', '-i', 's,SLAPD_OPTIONS=.*,SLAPD_OPTIONS="-l USER",', self.defaults])

        # setup slapd.conf
        subprocess.call(['sed', '-i', 's,^#allow bind_v2,allow bind_v2,', self.config])
        subprocess.call(['sed', '-i', 's,^loglevel.*,loglevel 200,', self.config])
        subprocess.call(['sed', '-i', 's#^suffix\(.*\)#suffix dc=example,dc=com\\nrootdn "cn=Manager,dc=example,dc=com"\\nrootpw {CRYPT}NA4V0VYvLWlU2#', self.config])
        subprocess.call(['sed', '-i', 's#cn=admin,dc=.*"#cn=admin,dc=example,dc=com"#', self.config])
        subprocess.call(['sed', '-i', 's#bdb#' + backend + '#', self.config])

        self.initdb_num_entries = 0

    def _initdb(self):
        '''Initialize slapd with some data'''

        # testuser's password is 'pass' and was generated with:
        # /usr/sbin/slappasswd -h {CRYPT}
        ldif_entries = '''#
# taken from debian postinst
dn: dc=example,dc=com
objectClass: top
objectClass: dcObject
objectClass: organization
o: example.com
dc: example

# taken from debian postinst
dn: cn=admin,dc=example,dc=com
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator
userPassword: {crypt}NA4V0VYvLWlU2

# Manager entry
dn: cn=Manager,dc=example,dc=com
objectClass: organizationalRole
cn: Manager

dn: ou=Users,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Users

dn: ou=Groups,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Groups

dn: ou=Contacts,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Contacts

dn: ou=Services,dc=example,dc=com
objectClass: top
objectClass: organizationalUnit
ou: Services

dn: uid=testuser,ou=Users,dc=example,dc=com
uid: testuser
cn: Test User
objectClass: account
objectClass: posixAccount
objectClass: top
userPassword: {CRYPT}NA4V0VYvLWlU2
loginShell: /bin/bash
uidNumber: 5000
gidNumber: 5000
homeDirectory: /home/testuser
gecos: Test User
description: Test User's account

dn: cn=Test Contact,ou=Contacts,dc=example,dc=com
cn: Test Contact
gn: Test
sn: Contact
o: Home
l: Some City
street: 1234 Sesame St
st: HI
postalCode: 96801
objectClass: top
objectClass: inetOrgPerson
'''

        # IMPORTANT: update this when adding entries to the above
        self.initdb_num_entries = 9

        self._modify(ldif_entries, True)

    def _tearDown(self):
        '''_tearDown'''
        self._stop()
        testlib.config_restore(self.defaults)
        testlib.config_restore(self.config)
        #testlib.config_restore(self.initscript)
        #subprocess.call(['chmod', '0755', self.initscript])

        os.unlink(self.config)

    def _stop(self):
        '''Shutdown server'''
        subprocess.call([self.initscript, 'stop'], stdout=subprocess.PIPE)
        time.sleep(1)

    def _start(self):
        '''Start server'''
        rc, report = testlib.cmd([self.initscript, 'start'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(2)

    def _restart(self):
        self._stop()
        self._start()

    def _word_find(self,report,name):
        '''Check for a specific string'''
        warning = 'Could not find "%s"\n' % name
        self.assertTrue(name in report, warning + report)

    def _modify(self, ldifstr, add=False, ignore=False, user="cn=Manager,dc=example,dc=com", password="pass"):
        '''ldapmodify wrapper'''
        handle, name = tempfile.mkstemp(prefix='add-ldif',dir='/tmp')
        handle = file(name,'w')
        handle.write(ldifstr)
        handle.close()

        lmopt = "-r"
        if add:
            lmopt = "-a"

        rc, report = testlib.cmd(['ldapmodify', '-x', '-D', user, '-w', password, lmopt, '-f', name])
        if not ignore:
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report + ldifstr)

        os.unlink(name)
        return report

    def _search(self, search, dn='cn=Manager,dc=example,dc=com', exp_entries=-1, password="pass"):
        '''ldapsearch wrapper'''
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', dn, '-w', password, '-x', '-b', 'dc=example,dc=com', search])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if exp_entries >= 1:
            self._word_find(report, "# numEntries: " + str(exp_entries))
        elif exp_entries == 0:
            name = "# numEntries: "
            warning = 'Found entries, but should not have: %s\n' % name
            self.assertFalse(name in report, warning + report)

        return report

    def _verifyConfig(self):
        '''Configuration file'''
        rc, report = testlib.cmd(['slaptest', '-f', self.config, '-v', '-d', '128', '-u'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _testDaemons(self, daemons):
        '''Daemons running'''
        for d in self.daemons:
            pidfile = os.path.join(self.rundir, d + ".pid")
            warning = "Could not find pidfile '" + pidfile + "'"
            self.assertTrue(os.path.exists(pidfile), warning)
            self.assertTrue(testlib.check_pidfile(d, pidfile))

    def _sendRawPacket(self, packet):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 389))
        s.sendall(packet)
        data = s.recv(1024)
        s.close()
        return data

class ServerGeneric(ServerCommon):
    '''Test Generic OpenLDAP server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

    def test_daemons(self):
        '''(ServerGeneric) Daemons running'''
        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_dn(self):
        '''(ServerGeneric) slapdn'''
        ServerCommon._initdb(self)
        rc, report = testlib.cmd(['slapdn', '-f', self.config, '-v', 'dc=example,dc=com'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_slapcat(self):
        '''(ServerGeneric) slapcat'''
        ServerCommon._initdb(self)
        handle, name = tempfile.mkstemp(prefix='slapcat',dir='/tmp')
        os.close(handle)
        rc, report = testlib.cmd(['slapcat', '-f', self.config, '-l', name])
        os.unlink(name)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_slapadd(self):
        '''(ServerGeneric) slapadd'''
        ServerCommon._initdb(self)
        self._stop()
        ldif = '''#
dn: uid=sasluser,ou=Users,dc=example,dc=com
uid: testslapadd
cn: Test Slapadd
objectClass: account
objectClass: posixAccount
objectClass: top
loginShell: /bin/bash
userPassword: pass
uidNumber: 5001
gidNumber: 5001
homeDirectory: /home/testslapadd
gecos: Test Slapadd
description: Test Slapadd's account
'''
        handle, name = tempfile.mkstemp(prefix='slapcat',dir='/tmp')
        handle = file(name,'w')
        handle.write(ldif)
        rc, report = testlib.cmd(['slapadd', '-f', self.config, '-l', name])
        os.unlink(name)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_apparmor(self):
        '''Test apparmor'''
        rc, report = testlib.check_apparmor('/usr/sbin/slapd', 8.04)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class ServerSimple(ServerCommon):
    '''Test OpenLDAP queries.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

    def test_daemons(self):
        '''(ServerSimple) Daemons running'''
        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_simpleBind(self):
        '''(ServerSimple) Simple bind'''

        # create directory tree and add user
        ServerCommon._initdb(self)

        rc, report = testlib.cmd(['ldapsearch', '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "# numEntries: %s" % str(self.initdb_num_entries))

    def test_simpleOps(self):
        '''(ServerSimple) ldap:// operations'''

        # create directory tree and add user
        ServerCommon._initdb(self)

        # bind as testuser with password
	self._search('(objectClass=*)', 'uid=testuser,ou=Users,dc=example,dc=com', self.initdb_num_entries)

        # search for certain object classes
        self._search('(objectClass=posixAccount)', 'uid=testuser,ou=Users,dc=example,dc=com', 1)

        # search for certain cn
        self._search('(&(objectClass=posixAccount)(cn=Test User))', 'uid=testuser,ou=Users,dc=example,dc=com', 1)

	# test modify delete (check for description, remove it, then check
        # again)
        self._search('(&(objectClass=posixAccount)(cn=Test User)(description=*))', 'uid=testuser,ou=Users,dc=example,dc=com', 1)

        ldif = '''#
dn: uid=testuser,ou=Users,dc=example,dc=com
changetype: modify
delete: description
description: Test User's account
'''
        self._modify(ldif)
        self._search('(&(objectClass=posixAccount)(cn=Test User)(description=*))', 'uid=testuser,ou=Users,dc=example,dc=com', 0)

	# test modify update (check loginShell, modify, then check again)
        self._search('(&(objectClass=posixAccount)(cn=Test User)(loginShell=/bin/bash))', 'uid=testuser,ou=Users,dc=example,dc=com', 1)

        ldif = '''#
dn: uid=testuser,ou=Users,dc=example,dc=com
changetype: modify
delete: loginShell
loginShell: /bin/bash
-
add: loginShell
loginShell: /bin/ksh
'''
        self._modify(ldif)
        self._search('(&(objectClass=posixAccount)(cn=Test User)(loginShell=/bin/ksh))', 'uid=testuser,ou=Users,dc=example,dc=com', 1)

        # test delete
        ldif = '''#
dn: uid=testuser,ou=Users,dc=example,dc=com
changetype: delete
'''
        self._modify(ldif)
        self._search('(objectClass=posixAccount)', 'cn=Manager,dc=example,dc=com', 0)

    def test_simplePassword(self):
        '''(ServerSimple) Passwords'''
        # create directory tree and add user
        ServerCommon._initdb(self)

        # change password
        newpass = "bar"
        rc, report = testlib.cmd(['ldappasswd', '-x', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', 'pass', '-s', newpass ])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test new password
	self._search('(objectClass=*)', 'uid=testuser,ou=Users,dc=example,dc=com', self.initdb_num_entries, newpass)

        # test old password
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', "pass", '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Old password worked' % rc

    def test_simpleFailures(self):
        '''(ServerSimple) Expected failures'''
        # create directory tree and add user
        ServerCommon._initdb(self)

        # bad host
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:388/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', "pass", '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Got exit code %d' % rc

        # bad search base
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', "pass", '-x', '-b', 'dc=example,dc=xxx', '(objectClass=*)'])
        assert rc != 0, 'Got exit code %d' % rc

        # bad DN
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:388/', '-D', 'uid=testuser,ou=Users,dc=example,dc=xxx', '-w', "pass", '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Got exit code %d' % rc

        # bad TLS
        rc, report = testlib.cmd(['ldapsearch', '-ZZ', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', "pass", '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Got exit code %d' % rc

        # bad password
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', "xxx", '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Got exit code %d' % rc


class ServerSimpleHDB(ServerSimple):
    '''Test OpenLDAP queries.'''
    def setUp(self):
        '''Setup mechanisms'''
        sys.stderr.write("(hdb) ... ")
        ServerCommon._setUp(self, "hdb")
        ServerCommon._restart(self)


class ServerSASL(ServerCommon):
    '''Test OpenLDAP SASL.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)

        subprocess.call(['sed', '-i', 's,^# SLAPD_SERVICES\(.*\),# SLAPD_SERVICES\\1\\nSLAPD_SERVICES="ldap:// ldapi://",', self.defaults])
        subprocess.call(['sed', '-i', 's#^loglevel\(.*\)#loglevel 496#', self.config])

        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

    def _searchSASL(self, search, user, password, exp_entries=-1, mech='DIGEST-MD5'):
        '''Ldapsearch wrapper'''
        rc, report = testlib.cmd(['ldapsearch', '-Y', mech, '-H', 'ldap://localhost:389/', '-U', user, '-w', password, '-b', 'dc=example,dc=com', search])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if exp_entries >= 1:
            self._word_find(report, "# numEntries: " + str(exp_entries))
        elif exp_entries == 0:
            name = "# numEntries: "
            warning = 'Found entries, but should not have: %s\n' % name
            self.assertFalse(name in report, warning + report)

    def test_daemons(self):
        '''(ServerSASL) Daemons running'''
        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_modules(self):
        '''(ServerSASL) Available modules'''
        modules = ['CRAM-MD5', 'DIGEST-MD5', 'NTLM', 'GSSAPI']

        # ldap:///
        rc, report = testlib.cmd(['ldapsearch', '-x', '-H', 'ldap:///', '-s', 'base', '-b', '', '-LLL', 'supportedSASLMechanisms'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for m in modules:
            str = "supportedSASLMechanisms: " + m
            self.assertTrue(str in report, str + " not in report:\n" + report)

        # ldapi:///
        modules += ['LOGIN', 'PLAIN', 'EXTERNAL']
        rc, report = testlib.cmd(['ldapsearch', '-x', '-H', 'ldapi:///', '-s', 'base', '-b', '', '-LLL', 'supportedSASLMechanisms'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        for m in modules:
            str = "supportedSASLMechanisms: " + m
            self.assertTrue(str in report, str + " not in report:\n" + report)

    def test_digest_md5(self):
        '''(ServerSASL) DIGEST-MD5 auth'''
        subprocess.call(['sed', '-i', 's#^argsfile\(.*\)#argsfile\\1\\npassword-hash {CLEARTEXT}\\nsaslRegexp\\n        uid=(.*),cn=digest-md5,cn=auth\\n        uid=$1,ou=Users,dc=example,dc=com#', self.config])
        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

        ServerCommon._initdb(self)

        # just store in openldap so we don't have to deal with sasldb2
        password = "{CLEARTEXT}foo"

        ldif = '''#
dn: uid=sasluser,ou=Users,dc=example,dc=com
uid: sasluser
cn: Sasl User
objectClass: account
objectClass: posixAccount
objectClass: top
loginShell: /bin/bash
userPassword: ''' + password + '''
uidNumber: 5001
gidNumber: 5001
homeDirectory: /home/sasluser
gecos: Sasl User
description: Sasl User's account
'''
        self._modify(ldif, True)

        # can we bind via sasl?
        self._searchSASL('cn=*user', 'sasluser', 'foo', 2)

        # change password via sasl
        newpass = "bar"
        rc, report = testlib.cmd(['ldappasswd', '-Y', 'DIGEST-MD5', '-H', 'ldap://localhost:389/', '-U', 'sasluser', '-w', 'foo', '-s', newpass ])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test new password via sasl
        self._searchSASL('cn=*user', 'sasluser', newpass, 2)

    def test_gssapi(self):
        '''(ServerSASL) GSSAPI auth'''
        ldap_principle = "ldapadmin"
        realm = "EXAMPLE.COM"
        ldap_fqdn = "ldap.example.com"

        self.keytab = "/etc/krb5.keytab"

        subprocess.call(['sed', '-i', 's#^argsfile\(.*\)#argsfile\\1\\nsasl-host ' + ldap_fqdn + '\\nsasl-realm ' + realm + '\\nsasl-secprops noplain,noanonymous,minssf=56\\nsaslRegexp\\n        uid=' + ldap_principle + ',cn=example.com,cn=gssapi,cn=auth\\n        uid=' + ldap_principle + ',cn=example.com,cn=gssapi,cn=auth\\nsaslRegexp\\n        uid=(.*),cn=gssapi,cn=auth\\n        uid=$1,ou=Users,dc=example,dc=com#', self.config])

        subprocess.call(['sed', '-i', 's#^rootpw.*##', self.config])
        subprocess.call(['sed', '-i', 's#^rootdn.*#rootdn  "uid=' + ldap_principle + ',cn=example.com,cn=gssapi,cn=auth"#', self.config])

        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

        rc, report = testlib.cmd(['klist'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        if ldap_principle not in report:
            return self._skipped("couldn't find '%s' in klist" % (ldap_principle))

        rc, report = testlib.cmd(['ldapsearch', '-x', '-H', 'ldap:///', '-s', 'base', '-b', '', '-LLL', 'supportedSASLMechanisms'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        str = "supportedSASLMechanisms: GSSAPI"
        self.assertTrue(str in report, str + " not in report:\n" + report)

        # test if proper resolution
        try:
            ip = socket.gethostbyname(ldap_fqdn)
        except:
            return self._skipped("'%s' doesn't resolve" % (ldap_fqdn))

        if ip == testlib.bogus_nxdomain:
            return self._skipped("'%s' resolves to bogus nxdomain" % \
                                   (ldap_fqdn))

        # make sure keytab is setup right
        if not os.path.exists(self.keytab):
            return self._skipped("'%s' does not exist" % (self.keytab))
        subprocess.call(['chown', self.uid + ':' + self.gid, self.keytab])
        subprocess.call(['chmod', '0640', self.keytab])

        try:
            reverse = socket.gethostbyaddr(ip)[0]
        except:
            return self._skipped("reverse lookup failed for '%s'" % \
                                   (ldap_fqdn))

        if reverse != ldap_fqdn:
            return self._skipped("reverse failed-- '%s' != '%s'" % \
                                   (reverse, ldap_fqdn))

        rc, report = testlib.cmd(['ldapwhoami', '-H', 'ldap://' + ldap_fqdn + '/'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


class ServerTLS(ServerCommon):
    '''Test OpenLDAP SSL and TLS.'''
    def setUp(self):
        '''Setup mechanisms'''
        self.current_dir = os.getcwd()
        ServerCommon._setUp(self)

        testlib.config_replace("/etc/hosts", "", True)
        subprocess.call(['sed', '-i', 's/^\\(127.0.0.1.*\\)/\\1 server client/g', "/etc/hosts"])

        (self.tmpdir, self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem) = testlib_ssl.gen_ssl()

        subprocess.call(['cp', self.srvcert_pem, os.path.join(self.datadir, "server.pem")])
        subprocess.call(['cp', self.srvkey_pem, os.path.join(self.datadir, "server.key")])
        subprocess.call(['cp', self.cacert_pem, os.path.join(self.datadir, "cacert.pem")])
        self.server_pem = self.datadir + "/server.pem"
        self.server_key = self.datadir + "/server.key"
        self.cacert_pem = self.datadir + "/cacert.pem"

        subprocess.call(['chown', self.uid + ':' + self.gid, self.server_pem])
        subprocess.call(['chgrp', self.gid, self.server_pem])
        subprocess.call(['chmod', '0440', self.server_pem])
        subprocess.call(['chown', self.uid + ':' + self.gid, self.server_key])
        subprocess.call(['chgrp', self.gid, self.server_key])
        subprocess.call(['chmod', '0440', self.server_key])
        subprocess.call(['chown', self.uid + ':' + self.gid, self.cacert_pem])
        subprocess.call(['chgrp', self.gid, self.cacert_pem])
        subprocess.call(['chmod', '0440', self.cacert_pem])

        subprocess.call(['sed', '-i', 's#^loglevel\(.*\)#loglevel 496\\1\\nTLSCACertificateFile   ' + self.cacert_pem + '\\nTLSCertificateFile     ' + self.server_pem + '\\nTLSCertificateKeyFile  ' + self.server_key + '#', self.config])

        subprocess.call(['sed', '-i', 's,^SLAPD_SERVICES\(.*\),SLAPD_SERVICES="ldap:// ldaps://",', self.defaults])

        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        os.chdir(self.current_dir)
        testlib.config_restore("/etc/hosts")
        ServerCommon._tearDown(self)

    def test_daemons(self):
        '''(ServerTLS) Daemons running'''
        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_tls(self):
        '''(ServerTLS) ldap:// (TLS)'''
        ServerCommon._initdb(self)

        try:
            os.chdir(self.datadir)
            fh = open(os.path.join(self.datadir, "ldaprc"), 'w')
            fh.write("TLS_REQCERT allow\n")
            fh.write("TLS_CACERT " + self.cacert_pem + "\n")
            fh.close()
        except:
            raise

        rc, report = testlib.cmd(['ldapsearch', '-ZZ', '-H', 'ldap://server:389/', '-D', "uid=testuser,ou=Users,dc=example,dc=com", '-w', 'pass', '-x', '-b', 'dc=example,dc=com', '(objectClass=posixAccount)' ])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "# numEntries: 1")

    def test_ssl(self):
        '''(ServerTLS) ldaps:// (SSL)'''
        ServerCommon._initdb(self)

        try:
            os.chdir(self.datadir)
            fh = open(os.path.join(self.datadir, "ldaprc"), 'w')
            fh.write("TLS_REQCERT allow\n")
            fh.write("TLS_CACERT " + self.cacert_pem + "\n")
            fh.close()
        except:
            raise

        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldaps://server:636/', '-D', "uid=testuser,ou=Users,dc=example,dc=com", '-w', 'pass', '-x', '-b', 'dc=example,dc=com', '(objectClass=posixAccount)' ])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "# numEntries: 1")

class ServerTLSNullByte(ServerCommon):
    '''Test OpenLDAP SSL with null-byte certs (CVE-2009-3767).'''
    def setUp(self):
        '''Setup mechanisms'''
        self.current_dir = os.getcwd()
        ServerCommon._setUp(self)

        testlib.config_replace("/etc/hosts", "", True)
        subprocess.call(['sed', '-i', 's/^\\(127.0.0.1.*\\)/\\1 www.bank.com/g', "/etc/hosts"])

        self.server_pem = os.path.join(self.datadir, "server.pem")
        self.server_key = os.path.join(self.datadir, "server.key")
        self.cacert_pem = os.path.join(self.datadir, "cacert.pem")

        subprocess.call(['cp', 'ssl/badguy-nul-cn.crt', self.server_pem])
        subprocess.call(['cp', 'ssl/badguy.key', self.server_key])
        subprocess.call(['cp', 'ssl/ca.crt', self.cacert_pem])

        subprocess.call(['chown', self.uid + ':' + self.gid, self.server_pem])
        subprocess.call(['chgrp', self.gid, self.server_pem])
        subprocess.call(['chmod', '0440', self.server_pem])
        subprocess.call(['chown', self.uid + ':' + self.gid, self.server_key])
        subprocess.call(['chgrp', self.gid, self.server_key])
        subprocess.call(['chmod', '0440', self.server_key])
        subprocess.call(['chown', self.uid + ':' + self.gid, self.cacert_pem])
        subprocess.call(['chgrp', self.gid, self.cacert_pem])
        subprocess.call(['chmod', '0440', self.cacert_pem])

        subprocess.call(['sed', '-i', 's#^loglevel\(.*\)#loglevel 496\\1\\nTLSCACertificateFile   ' + self.cacert_pem + '\\nTLSCertificateFile     ' + self.server_pem + '\\nTLSCertificateKeyFile  ' + self.server_key + '#', self.config])

        subprocess.call(['sed', '-i', 's,^SLAPD_SERVICES\(.*\),SLAPD_SERVICES="ldap:// ldaps://",', self.defaults])

        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        os.chdir(self.current_dir)
        testlib.config_restore("/etc/hosts")
        ServerCommon._tearDown(self)

    def test_daemons(self):
        '''(ServerTLSNullByte) Daemons running'''
        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_ssl(self):
        '''(ServerTLSNullByte) ldaps:// (SSL)'''
        ServerCommon._initdb(self)

        try:
            os.chdir(self.datadir)
            fh = open(os.path.join(self.datadir, "ldaprc"), 'w')
            fh.write("TLS_REQCERT demand\n")
            fh.write("TLS_CACERT " + self.cacert_pem + "\n")
            fh.close()
        except:
            raise

        if self.lsb_release['Release'] <= 14.04:
            expected  = 255
            error_str = "TLS: unable to get common name from peer certificate"
        else:
            expected  = 255
            error_str = "TLS: hostname (www.bank.com) does not match common name in certificate"

        rc, report = testlib.cmd(['ldapsearch', '-d', '200', '-H', 'ldaps://www.bank.com:636/', '-D', "uid=testuser,ou=Users,dc=example,dc=com", '-w', 'pass', '-x', '-b', 'dc=example,dc=com', '(objectClass=posixAccount)' ])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, error_str)

class ServerIPC(ServerCommon):
    '''Test OpenLDAP IPC.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)

        subprocess.call(['sed', '-i', 's,^# SLAPD_SERVICES\(.*\),# SLAPD_SERVICES\\1\\nSLAPD_SERVICES="ldap:// ldapi://",', self.defaults])

        ServerCommon._verifyConfig(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

    def test_daemons(self):
        '''(ServerIPC) Daemons running'''
        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_ipc(self):
        '''(ServerIPC) ldapi:///'''
        ServerCommon._initdb(self)

        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldapi:///', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', 'pass', '-x', '-b', 'dc=example,dc=com', '(objectClass=posixAccount)'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "# numEntries: 1")


class ServerCVEs(ServerCommon):
    '''Test OpenLDAP against CVEs.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._restart(self)

        # populate with some entries
        ServerCommon._initdb(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

    def test_CVE_2007_5707(self):
        '''(ServerCVEs) CVE-2007-5707'''

        ldif = '''#
dn: uid=cve20075707,ou=Users,dc=example,dc=com
objectClasses: top
'''
        self._modify(ldif, True, True)

        # wait for it to actually die
        time.sleep(5)

        self.daemons = [ "slapd" ]
        ServerCommon._testDaemons(self, self.daemons)

    def test_CVE_2008_2952(self):
        '''(ServerCVEs) CVE-2008-2952'''

        self.daemons = [ "slapd" ]
        # Server running
        self._testDaemons(self.daemons)
        # Server does not respond to garbage
        self.assertEquals(self._sendRawPacket('\xff\xff\xff\x00\x84ABCD'),'')
        # Server has not crashed
        self._testDaemons(self.daemons)

    def test_CVE_2010_0211(self):
        '''(ServerCVEs) CVE-2010-0211'''

        self.daemons = [ "slapd" ]
        # Server running
        self._testDaemons(self.daemons)

	for i in range(100):
            rc, report = testlib.cmd(['ldapmodrdn', '-x', 'dc=example,dc=com', 'cn=#80'])

        self._testDaemons(self.daemons)

    def test_CVE_2010_0212(self):
        '''(ServerCVEs) CVE-2010-0212'''

        self.daemons = [ "slapd" ]
        # Server running
        self._testDaemons(self.daemons)

        rc, report = testlib.cmd(['ldapmodrdn', '-x', 'dc=example,dc=com', 'dc='])

        self._testDaemons(self.daemons)

    def test_CVE_2011_1081(self):
        '''(ServerCVEs) CVE-2011-1081'''
        self.daemons = [ "slapd" ]
        # Server running
        self._testDaemons(self.daemons)

        rc, report = testlib.cmd(['ldapmodrdn', '-x', '-H', 'ldap://localhost', '-r', '', 'o=test'])

        self._testDaemons(self.daemons)

    def test_CVE_2011_4079(self):
        '''(ServerCVEs) CVE-2011-4079'''

        # verify postalAddress is not present
        self._search('(&(objectClass=inetOrgPerson)(cn=Test Contact)(postalAddress=*))', 'cn=Manager,dc=example,dc=com', 0)

	# add a postalAddress
        good_split_address = '''ITD Prod Dev & Deployment $ 535 W. William St. Room 4212 $ Anyt
 own, MI 48103-4943'''
        good_address = '''ITD Prod Dev & Deployment $ 535 W. William St. Room 4212 $ Anytown, MI 48103-4943'''

        # add the split address
        ldif = '''#
dn: cn=Test Contact,ou=Contacts,dc=example,dc=com
changetype: modify
add: postalAddress
postalAddress: %s
''' % good_split_address
        self._modify(ldif)

        # check for the unsplit address
        out = self._search('(&(objectClass=inetOrgPerson)(cn=Test Contact)(postalAddress=%s))' % good_address, 'cn=Manager,dc=example,dc=com', 1)

        # delete the postalAddress to clean up
        ldif = '''#
dn: cn=Test Contact,ou=Contacts,dc=example,dc=com
changetype: modify
delete: postalAddress
postalAddress: %s
''' % (good_split_address)
        self._modify(ldif)
        self._search('(&(objectClass=inetOrgPerson)(cn=Test Contact)(postalAddress=%s))' % good_address, 'cn=Manager,dc=example,dc=com', 0)

        for addr in ['Some Dept $ 1234 Some Street $ Some Town, SS 00001', '$$', '\x01', '', good_split_address]:
            # add address
            ldif = '''#
dn: cn=Test Contact,ou=Contacts,dc=example,dc=com
changetype: modify
add: postalAddress
postalAddress: %s
''' % (addr)
            self._modify(ldif)

            search = addr
            if addr == good_split_address:
                search = good_address
            #print "  %s" % search

            out = self._search('(&(objectClass=inetOrgPerson)(cn=Test Contact)(postalAddress=%s))' % search, 'cn=Manager,dc=example,dc=com', 1)

            # delete address
            ldif = '''#
dn: cn=Test Contact,ou=Contacts,dc=example,dc=com
changetype: modify
delete: postalAddress
postalAddress: %s
''' % (addr)
            self._modify(ldif)
            out = self._search('(&(objectClass=inetOrgPerson)(cn=Test Contact)(postalAddress=%s))' % search, 'cn=Manager,dc=example,dc=com', 0)

        out = self._search('(&(objectClass=inetOrgPerson)(cn=Test Contact))', 'cn=Manager,dc=example,dc=com', 1)
        #print out

class ServerOverlays(ServerCommon):
    '''Test OpenLDAP Overlay functionality.'''
    def _stop(self):
        '''Shutdown server'''
        subprocess.call([self.initscript, 'stop'], stdout=subprocess.PIPE)
        time.sleep(3)
        subprocess.call(['killall', 'slapd'], stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        time.sleep(1)

    def _start(self):
        '''Start server'''
        rc, report = testlib.cmd([self.initscript, 'start'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        args = ['slapd', '-g', self.gid, '-u', self.uid, '-f',
                "/etc/ldap/slapd-pcache.conf", '-l', 'USER', '-h',
                'ldap://localhost:390/']

        if os.path.exists("/etc/ldap/slapd-pcache.conf"):
            rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        time.sleep(2)

    def _restart(self):
        self._stop()
        self._start()

    def _pcache_dbstat(self):
        '''Returns cache hits'''
        handle, name = tempfile.mkstemp(prefix='dbstatout',dir='/tmp')
        handle = file(name,'w')

        exe = 'db5.1_stat'
        if self.lsb_release['Release'] >= 14.04:
            exe = 'db5.3_stat'

        rc, report = testlib.cmd(['which', exe])
        expected = 0
        result = "Could not find '%s'\n" % (exe)
        self.assertEquals(expected, rc, result + report)

        subprocess.call([exe, '-m', '-h', self.extra_dbdir], stdout=handle)
        handle.close()

        fh = open(name, 'r')
        lines = fh.readlines()
        fh.close()
        os.unlink(name)

        line = ""
        found_id = False
        pat_id = re.compile(r'id2entry.bdb')
        for line in lines:
            if not found_id:
                if pat_id.search(line):
                    found_id = True
            else:
                if re.search(r'Requested pages found in the cache', line):
                    return int(line.split()[0])
        return -1


    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        if os.path.exists('/sbin/apparmor_parser'):
            # various overlays use different directories for backends, so disable
            # the profile for now
            #print "\nDEBUG: Disabling AppArmor profile for /usr/sbin/slapd"
            testlib.cmd(['/sbin/apparmor_parser', '-R', '/etc/apparmor.d/usr.sbin.slapd'])
        ServerCommon._restart(self)

        self.extra_dbdir = ""
        self.extra_conf = ""

    def tearDown(self):
        '''Shutdown methods'''
        self._stop()
        if os.path.exists(self.extra_dbdir):
            testlib.recursive_rm(self.extra_dbdir)

        if os.path.exists(self.extra_conf):
            os.unlink(self.extra_conf)

        ServerCommon._tearDown(self)
        if os.path.exists('/usr/sbin/aa-enforce'):
            testlib.cmd(['aa-enforce', '/usr/sbin/slapd'])

    def test_pcache(self):
        '''(ServerOverlays) Proxy and ProxyCache'''

        self.extra_dbdir = "/var/lib/ldap-pcache"
        self.extra_conf = "/etc/ldap/slapd-pcache.conf"

        # release specific config
        pcache_name = "pcache"
	added_modules = '''#
moduleload      back_ldap
'''
        # pcache config
        pconf = '''#
allow bind_v2
include         /etc/ldap/schema/core.schema
include         /etc/ldap/schema/cosine.schema
include         /etc/ldap/schema/nis.schema
include         /etc/ldap/schema/inetorgperson.schema
pidfile         ''' + self.rundir + '''/slapd-pcache.pid
argsfile        ''' + self.rundir + '''/slapd-pcache.args
loglevel        200
modulepath      /usr/lib/ldap
moduleload      back_bdb
moduleload      pcache
''' + added_modules + '''
sizelimit       500
tool-threads    1
database        ldap
suffix          "dc=example,dc=com"
rootdn          "dc=example,dc=com"
uri             "ldap://localhost:389/dc=example%2cdc=com"
overlay         ''' + pcache_name + '''
proxycache      bdb 100000 1 1000 100
# for some reason openldap 2.2 likes only one attr in proxyAttrset
proxyAttrset    0 uidNumber
proxyTemplate   (cn=) 0 3600
proxyTemplate   (uid=) 0 3600
proxyTemplate   (&(objectClass=)(cn=)) 0 3600
proxyTemplate   (&(objectClass=)(uid=)) 0 3600
cachesize       20
directory       ''' + self.extra_dbdir + '''
dbconfig set_cachesize 0 2097152 0
index       objectClass eq
index       cn,uid  pres,eq,sub
'''
        try:
            fh = open(self.extra_conf, 'w')
            fh.write(pconf)
            fh.close()
        except:
            raise

        os.makedirs(self.extra_dbdir)
        subprocess.call(['chown', self.uid + ':' + self.gid, self.extra_dbdir])

        self._restart()

        # check both are running
        for d in ['slapd', 'slapd-pcache']:
            pidfile = os.path.join(self.rundir, d + ".pid")
            warning = "Could not find pidfile '" + pidfile + "'"
            self.assertTrue(os.path.exists(pidfile), warning)
            self.assertTrue(testlib.check_pidfile("slapd", pidfile))

        # populate initially
        ServerCommon._initdb(self)

        hits = self._pcache_dbstat()
        assert hits >= 0, "Bad db stats"

        # test the proxy
        rc, report = testlib.cmd(['ldapsearch', '-x', '-H', 'ldap://localhost:390/', '-b', 'dc=example,dc=com', '(&(objectClass=posixAccount)(uid=testuser))', 'uidNumber'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "# numEntries: 1")
        # for some reason, this is needed...
        time.sleep(3)

        newhits = self._pcache_dbstat()
        assert newhits > hits, "Cache miss '" + str(newhits) + " < " + str(hits) + "'"

    def test_accesslog(self):
        '''(ServerOverlays) accesslog'''
        # See man slapo-accesslog
        self.extra_dbdir = "/var/lib/ldap-accesslog"

        # append our changes to slapd.conf
        contents = file(self.config).read()
        contents += '''
# add accesslog overlay to main database
overlay accesslog
logdb "cn=accesslog"
logops writes reads

# new database for accesslog
database hdb
suffix "cn=accesslog"
directory       "%s"
''' % (self.extra_dbdir)
        open(self.config, 'w').write(contents)

        subprocess.call(['sed', '-i', 's,^#EXTRA_MODULE_LOADS,moduleload accesslog,', self.config])

        os.makedirs(self.extra_dbdir)
        subprocess.call(['chown', self.uid + ':' + self.gid, self.extra_dbdir])

        self._restart()

        # test the accesslog
        rc, report = testlib.cmd(['ldapsearch', '-x', '-H', 'ldap://localhost:389/', '-b', 'cn=accesslog'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "result: 0 Success")

    def test_ppolicy(self):
        '''(ServerOverlays) ppolicy'''
        schema = "/etc/ldap/schema/ppolicy.schema"

        if not os.path.exists(schema):
            return self._skipped("Could not find '%s'" % schema)

        # initial password is too weak with ppolicy, so init the db first
        ServerCommon._initdb(self)

        # append our changes to slapd.conf
        contents = file(self.config).read()

        # See man slapo-ppolicy
        # http://www.symas.com/blog/?page_id=66
        # http://www.zytrax.com/books/ldap/ch6/ppolicy.html
        contents += '''
# add ppolicy overlay to main database. NOTE: this effectively disables the
# cn=Manager,dc=example,dc=com defined in this file (use cn=admin,dc=example,dc=com
# instead)
overlay ppolicy
ppolicy_default "cn=default,ou=policies,dc=example,dc=com"
# Normally, when a user binds to an account that has been locked, the password
# policy module will return an INVALID CREDENTIALS (49) error, even if the
# password policy request control was included with the bind request. This is
# done because providing an ACCOUNT LOCKED return code would provide useful
# information to an attacker. To ease testing, return ACCOUNT LOCKED instead.
ppolicy_use_lockout
'''
        open(self.config, 'w').write(contents)

        subprocess.call(['sed', '-i', 's,^#EXTRA_MODULE_LOADS,moduleload ppolicy,', self.config])
        subprocess.call(['sed', '-i', 's,^#EXTRA_INCLUDES,include %s,' % schema, self.config])

        self._restart()

        ldif = '''# Password policy container
dn: ou=policies,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: policies

# add default policy to DIT
dn: cn=default,ou=policies,dc=example,dc=com
cn: default
objectClass: pwdPolicy
objectClass: person
objectClass: top
pwdAllowUserChange: TRUE
pwdAttribute: userPassword
pwdCheckQuality: 2
pwdExpireWarning: 600
pwdFailureCountInterval: 30
pwdGraceAuthNLimit: 5
pwdInHistory: 5
pwdLockout: TRUE
pwdLockoutDuration: 0
pwdMaxAge: 0
pwdMaxFailure: 5
pwdMinAge: 0
pwdMinLength: 4
pwdMustChange: FALSE
pwdSafeModify: FALSE
sn: dummy value
'''

        # use cn=admin,dc=example,dc=com since ppolicy doesn't seem to like using
        # cn=Manager,dc=example,dc=com (which is defined in slapd.conf)
        self._modify(ldif, add=True, ignore=False, user='cn=admin,dc=example,dc=com', password='pass')

        # change password -- too short
        newpass = "bar"
        rc, report = testlib.cmd(['ldappasswd', '-x', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', 'pass', '-s', newpass ])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        newpass = "1234"
        rc, report = testlib.cmd(['ldappasswd', '-x', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', 'pass', '-s', newpass ])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test new password
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', newpass, '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc == 0, 'New password did not work' % rc

        # test old password
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', "pass", '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Old password worked' % rc

        # create a ppolicy with minimum password length of '8'
        ldif = '''#
# add a user specific policy to DIT
dn: cn=testuser,ou=policies,dc=example,dc=com
cn: testuser
objectClass: pwdPolicy
objectClass: person
objectClass: top
pwdAllowUserChange: TRUE
pwdAttribute: userPassword
pwdCheckQuality: 2
pwdExpireWarning: 600
pwdFailureCountInterval: 30
pwdGraceAuthNLimit: 5
pwdInHistory: 5
pwdLockout: TRUE
pwdLockoutDuration: 0
pwdMaxAge: 0
pwdMaxFailure: 5
pwdMinAge: 0
pwdMinLength: 8
pwdMustChange: FALSE
pwdSafeModify: FALSE
sn: dummy value
'''
        self._modify(ldif, add=True, ignore=False, user='cn=admin,dc=example,dc=com', password='pass')

        # now associate the new policy with the user
        ldif = '''#
dn: uid=testuser,ou=Users,dc=example,dc=com
changetype: modify
add: pwdPolicySubentry
pwdPolicySubentry: cn=testuser,ou=policies,dc=example,dc=com
'''
        self._modify(ldif, add=False, ignore=False, user='cn=admin,dc=example,dc=com', password='pass')

        # change password -- too short
        newpass2 = "1234567"
        rc, report = testlib.cmd(['ldappasswd', '-x', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', newpass, '-s', newpass2 ])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        newpass2 = "12345678"
        rc, report = testlib.cmd(['ldappasswd', '-x', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', newpass, '-s', newpass2 ])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test new password
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', newpass2, '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc == 0, 'New password did not work' % rc

        # test old password
        rc, report = testlib.cmd(['ldapsearch', '-H', 'ldap://localhost:389/', '-D', 'uid=testuser,ou=Users,dc=example,dc=com', '-w', newpass, '-x', '-b', 'dc=example,dc=com', '(objectClass=*)'])
        assert rc != 0, 'Old password worked' % rc


class ServerCnconfig(ServerCommon):
    '''Test OpenLDSP cnconfig functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)

        self.cnconfig_dir = "/etc/ldap/slapd.d"

        testlib.config_copydir(self.cnconfig_dir)
        testlib.recursive_rm(self.cnconfig_dir)

        os.mkdir(self.cnconfig_dir)
        subprocess.call(['chown', self.uid + ':' + self.gid, self.cnconfig_dir])

        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        testlib.recursive_rm(self.cnconfig_dir)

        testlib.config_restore(self.cnconfig_dir)
        subprocess.call(['chown', "-R", self.uid + ':' + self.gid, self.cnconfig_dir])
        ServerCommon._tearDown(self)

    def test_convert(self):
        '''(ServerCnconfig) converting slapd.conf to cnconfig (slapd.d)'''

        ServerCommon._initdb(self)
        ServerCommon._stop(self)

        rc, report = testlib.cmd(['slapd', '-g', self.gid, '-u', self.uid, '-f', self.config, '-F', self.cnconfig_dir])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        time.sleep(3)
        self.assertFalse(len(os.listdir(self.cnconfig_dir)) == 0)

        ServerCommon._start(self)

class OpenLDAPTestSuite(testlib.TestlibCase):
    '''Testsuite for OpenLDAP'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.builder = testlib.TestUser()
        testlib.cmd(['chgrp', self.builder.login, self.tmpdir])
        os.chmod(self.tmpdir, 0775)
        self.patch_system = "quilt"

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.builder = None
        os.chdir(self.topdir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)
        if os.path.exists(self.cached_src):
            testlib.recursive_rm(self.cached_src)


class ServerStub(ServerCommon):
    '''Debugging stub.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        #ServerCommon._tearDown(self)
        pass

    def test_stub(self):
        '''(ServerStub) test_stub'''
        ServerCommon._initdb(self)

#
# MAIN
#
if __name__ == '__main__':
    assert not os.path.isdir("/var/lib/ldap.autotest")
    subprocess.call(['mv', "/var/lib/ldap", "/var/lib/ldap.autotest"])

    suite = unittest.TestSuite()

    # add tests here
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerGeneric))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerSimple))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerSimpleHDB))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerIPC))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerSASL))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerTLS))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerTLSNullByte))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerOverlays))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerCVEs))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerCnconfig))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(OpenLDAPTestSuite))

    # only use for debugging-- it doesn't cleanup
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerStub))

    # run tests
    rc = unittest.TextTestRunner(verbosity=2).run(suite)

    # make sure slapd isn't running
    print "Killing stray slapd processes"
    subprocess.call(['killall', 'slapd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['killall', 'slurd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if os.path.exists("/var/lib/ldap"):
        testlib.recursive_rm("/var/lib/ldap")
    subprocess.call(['mv', "/var/lib/ldap.autotest", "/var/lib/ldap"])

    if not rc.wasSuccessful():
        sys.exit(1)
