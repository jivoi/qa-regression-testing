#!/usr/bin/python
#
#    test-mysql.py quality assurance test script
#    Copyright (C) 2008-2013 Canonical Ltd.
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
    How to run against a clean schroot named 'dapper'
    (must manually set mysql root password to 'pass'):
        schroot -c dapper -u root -- sh -c 'apt-get -y install mysql-server mysql-client lsb-release openssl && sudo ./test-mysql.py -v'

    How to run against a clean schroot named 'hardy'
    (automatically sets mysql root password to 'pass'):
        schroot -c hardy -u root -- sh -c 'apt-get -y install mysql-server mysql-client lsb-release python-apt openssl && sudo ./test-mysql.py -v'

    Notes:
      On Hardy and later, now does dpkg-reconfigure to reset the root password to 'pass'
      Dapper: after install, do 'sudo /etc/init.d/mysql reset-password' to set
              the root password)
      On Lucid, mysql-server doesn't run in a chroot. A VM must be used for testing.

    TODO:
      - more thorough SQL (hint: http://dev.mysql.com/doc/sakila/en/sakila.html)
      - different database backends (hint: redo employees-db tests for each backend)
      - better mariadb / percona support
'''

# QRT-Depends: mysql testlib_ssl.py
# QRT-Packages: mysql-server mysql-client openssl python-apt
# QRT-Alternates: mysql-testsuite
# QRT-Privilege: root

import unittest, subprocess, os, sys, pwd, shutil, time
from tempfile import mkstemp, mkdtemp
import testlib
import testlib_ssl

def mycmd(command, stdin=None, stdout=subprocess.PIPE, stderr=None):
    '''Try to execute command'''
    try:
        sp = subprocess.Popen(command, stdin=stdin, stdout=stdout, stderr=stderr)
    except OSError, e:
        return [127, str(e)]
    out = sp.communicate()[0]
    return [sp.returncode,out]

default_pass = 'pass'

def initial_setup():

        # python-apt on dapper and hardy doesn't have the same API
        if testlib.ubuntu_release() == "dapper" or \
           testlib.ubuntu_release() == "hardy":
            server = "mysql-server-5.0"
        else:
            import apt
            cache = apt.Cache()
            cache.open()
            server = None
            for p in ['mariadb-server-5.5', 'mysql-server-5.5', 'mysql-server-5.1', 'mysql-server-5.0']:
                if cache.__contains__(p) and cache[p].is_installed:
                    server = p
                    break

        handle, debconf = testlib.mkstemp_fill('''Name: mysql-server/root_password
Template: mysql-server/root_password
Value: %s
Owners: %s

Name: mysql-server/root_password_again
Template: mysql-server/root_password_again
Value: %s
Owners: %s''' %((default_pass, server) * 2))
        env = os.environ.copy()
        env['DEBIAN_FRONTEND']= 'noninteractive'
        env['DEBCONF_DB_OVERRIDE'] = 'File{%s}' %debconf
        handle.close()
        subprocess.call(['dpkg-reconfigure', server], env=env, stdout=subprocess.PIPE)
        os.unlink(debconf)

class ServerCommon(testlib.TestlibCase):
    '''Common server routines'''

    def _setUp(self):
        '''_setUp'''
        self.rootpass = default_pass
        self.initscript = "/etc/init.d/mysql"
        self.rundir = "/var/run/mysqld"
	self.handle, self.name = testlib.mkstemp_fill('''show databases;
create database foo;
drop database foo;
connect mysql;
show tables;
select * from user;
''', dir="/tmp")
        self.mysql_commonargs = ['--no-defaults', '-u', 'root', '--password=' + self.rootpass]
        self.mysql_commoncmd = ['/usr/bin/mysql'] + self.mysql_commonargs

        # make sure the real mysql is not running
        subprocess.call([self.initscript, 'stop'], stdout=subprocess.PIPE)

    def _tearDown(self):
        '''_tearDown'''
        self._stop()
        self.handle.close()
        os.unlink(self.name)

    def _stop(self):
        '''Shutdown server'''
        subprocess.call([self.initscript, 'stop'], stdout=subprocess.PIPE)
        time.sleep(3)
        subprocess.call(['killall', 'mysqld'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # workaround for https://bugs.launchpad.net/ubuntu/+source/mysql-dfsg-5.0/+bug/105457
        subprocess.call(['killall', 'mysqld_safe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.call(['killall', '-9', 'mysqld_safe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _start(self):
        '''Start server'''
        rc, report = testlib.cmd([self.initscript, 'start'], None, stderr=None)
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

    def _testDaemons(self, daemons):
        '''Daemons running'''
        for d in self.daemons:
            pidfile = os.path.join(self.rundir, d + ".pid")
            warning = "Could not find pidfile '" + pidfile + "'"
            self.assertTrue(os.path.exists(pidfile), warning)
            self.assertTrue(testlib.check_pidfile("mysqld", pidfile))


class ServerGeneric(ServerCommon):
    '''Test Generic mysql server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

    def test_daemons(self):
        '''(ServerGeneric) Daemons running'''

        if self.lsb_release['Release'] <= 9.10:
            self.daemons = [ "mysqld" ]
            ServerCommon._testDaemons(self, self.daemons)
        else:
            print "(skipped: Lucid and newer(?) don't use mysql.pid)"


    def test_initscript(self):
        '''(ServerGeneric) Initscript'''
        subprocess.call(['/etc/init.d/mysql', 'stop'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.call(['/etc/init.d/mysql', 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.call(['/etc/init.d/mysql', 'restart'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.call(['/etc/init.d/mysql', 'reload'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.call(['/etc/init.d/mysql', 'force-reload'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.call(['/etc/init.d/mysql', 'status'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_apparmor(self):
        '''Test apparmor'''
        rc, report = testlib.check_apparmor('/usr/sbin/mysqld', 8.04, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

class ServerSimple(ServerCommon):
    '''Test simple mysql server functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._restart(self)

        self.mycnf = "/etc/mysql/my.cnf"
        testlib.config_replace(self.mycnf, "", True)
        subprocess.call(['sed', '-i', 's,^\[mysqld\],[mysqld]\\nlog = /var/log/mysql.log\\n,g', self.mycnf])

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)
        testlib.config_restore(self.mycnf)

    def test_default(self):
        '''(ServerSimple) Default protocol'''
        self.assertShellExitEquals(0, self.mysql_commoncmd + ['-h','localhost'], stdin=self.handle)

    def test_socket(self):
        '''(ServerSimple) Socket'''
	self.assertShellExitEquals(0, self.mysql_commoncmd + ['--protocol=SOCKET'], stdin=self.handle)

    def test_tcp(self):
        '''(ServerSimple) TCP'''
	self.assertShellExitEquals(0, self.mysql_commoncmd + ['-h','127.0.0.1','--protocol=TCP'], stdin=self.handle)

class ServerSSL(ServerCommon):
    '''Test mysql server SSL functionality.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._stop(self)

        if self.lsb_release['Release'] == 6.06:
            return True

	self.sslhandle, self.sslname = testlib.mkstemp_fill('''SHOW VARIABLES LIKE 'have_ssl';''', dir="/tmp")

        (self.tmpdir, self.srvcert_pem, self.srvkey_pem, self.clientcert_pem, self.clientkey_pem, self.cacert_pem) = testlib_ssl.gen_ssl()

        subprocess.call(['chown', '-R', 'mysql', self.tmpdir])

        self.hosts = "/etc/hosts"
        testlib.config_replace(self.hosts, "", True)
        subprocess.call(['sed', '-i', 's/^\\(127.0.0.1.*\\)/\\1 server client/g', self.hosts])

        self.mycnf = "/etc/mysql/my.cnf"
        testlib.config_replace(self.mycnf, "", True)
        subprocess.call(['sed', '-i', 's,^\[mysqld\],[mysqld]\\nssl\\n\\nssl-ca=' + self.cacert_pem + '\\nssl-cert=' + self.srvcert_pem + '\\nssl-key=' + self.srvkey_pem + '\\nlog = /var/log/mysql.log\\n,g', self.mycnf])
        subprocess.call(['sed', '-i', 's,^\[client\],[client]\\nssl\\n\\nssl-ca=' + self.cacert_pem + '\\nssl-cert=' + self.clientcert_pem + '\\nssl-key=' + self.clientkey_pem + '\\nssl-verify-server-cert = false\\n,g', self.mycnf])

        ServerCommon._restart(self)

    def tearDown(self):
        '''Shutdown methods'''
        ServerCommon._tearDown(self)

        if self.lsb_release['Release'] == 6.06:
            return True

        self.sslhandle.close()
        os.unlink(self.sslname)

        testlib.config_restore(self.mycnf)
        testlib.config_restore(self.hosts)
        testlib.recursive_rm(self.tmpdir)

    def test_ssl(self):
        '''(ServerSSL) SSL connections'''

        if self.lsb_release['Release'] == 6.06:
            print "Dapper not compiled with SSL"
            return True

        # wait around for 'Checking for crashed tables' to finish
        for i in range(60):
            time.sleep(2)
	    (rc, report) = mycmd(self.mysql_commoncmd + ['-h','server', '--protocol=TCP', '--ssl', '--ssl-ca=' + self.cacert_pem, '--ssl-cert=' + self.clientcert_pem, '--ssl-key=' + self.clientkey_pem], stdin=self.sslhandle, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if rc == 0:
                break
        self.assertEquals(0, rc, report)


class ServerDataTest(ServerCommon):
    '''Test database functionality with the employees db.'''
    def setUp(self):
        '''Setup mechanisms'''
        ServerCommon._setUp(self)
        ServerCommon._restart(self)

	self.dumphandle, self.dumpname = mkstemp(dir="/tmp")

        self.mydir = os.getcwd()

        # Disable bin-logs
        self.mycnf = "/etc/mysql/my.cnf"
        testlib.config_replace(self.mycnf, "", True)
        subprocess.call(['sed', '-i', 's,^log-bin.*$,,g', self.mycnf])

        try:
            os.chdir("mysql/employees_db")
        except:
            raise
        subprocess.call(['sed', '-i', 's,^\\( \\)\\+set storage_engine = .*,\\1set storage_engine = InnoDB;,g', 'employees.sql'])

    def tearDown(self):
        '''Shutdown methods'''

        # Clean up database
        self._drop_database()
        subprocess.call(['sed', '-i', 's,^\\( \\)\\+set storage_engine = .*,\\1set storage_engine = InnoDB;,g', 'employees.sql'])

        os.close(self.dumphandle)
        os.unlink(self.dumpname)

        ServerCommon._tearDown(self)

        testlib.config_restore(self.mycnf)

        try:
            os.chdir(self.mydir)
        except:
            raise

    def _corrupt_database(self):
        '''(ServerDataTest) Corrupts the database'''
        self.assertShellExitEquals(0, self.mysql_commoncmd + ['-h','localhost','employees','-e','UPDATE employees SET first_name="Marc" WHERE first_name="Marke";'])

    def _import_database(self,dbfile):
        '''(ServerDataTest) Imports the database'''
        self.assertShellExitEquals(0, self.mysql_commoncmd + ['-h','localhost'], stdin=file(dbfile))

    def _test_database(self):
        '''(ServerDataTest) Tests the database'''
	(rc, report) = testlib.cmd(self.mysql_commoncmd + ['-h','localhost','-t'], stdin=file('test_employees_md5.sql'))

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Checksums didn't match the data in the InnoDB database\n"
        self.assertEquals(report.find("not ok"), -1, result + report)

    def _drop_database(self):
        '''(ServerDataTest) Drops the database'''
        self.assertShellExitEquals(0, self.mysql_commoncmd + ['-h','localhost','-e','drop database if exists employees;'])

    def test_innodb(self):
        '''(ServerDataTest) Testing InnoDB storage'''
        self._import_database("employees.sql")

        self._test_database()

    def test_myisam(self):
        '''(ServerDataTest) Testing MyISAM storage'''
        subprocess.call(['sed', '-i', 's,^\\( \\)\\+set storage_engine = .*,\\1set storage_engine = MyISAM;,g', 'employees.sql'])
        self._import_database("employees.sql")

        self._test_database()

    def test_mysqldump(self):
        '''(ServerDataTest) Testing mysqldump'''
        self._import_database("employees.sql")

        # Dump the database
	(rc, report) = testlib.cmd(['/usr/bin/mysqldump'] + self.mysql_commonargs + ['-h','localhost','--databases','employees'], stdout=self.dumphandle)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

        # Corrupt the data to make sure the database gets dropped and reimported
        self._corrupt_database()

        # Drop the database
        self._drop_database()

        # Reimport the database from the dump
        self._import_database(self.dumpname)

        # Corrupt the data to test the test
        #self._corrupt_database()

	self._test_database()

    def test_mysql_convert_table_format(self):
        '''(ServerDataTest) Testing mysql_convert_table_format'''

        print "\n  importing as MyISAM..."
        subprocess.call(['sed', '-i', 's,^\\( \\)\\+set storage_engine = .*,\\1set storage_engine = MyISAM;,g', 'employees.sql'])
        self._import_database("employees.sql")

        print "  verifying import..."
        self._test_database()

        print "  converting employees table to InnoDB..."
	(rc, report) = testlib.cmd(['/usr/bin/mysql_convert_table_format', '--host','localhost','--type=InnoDB', '--user=root', '--password=%s' % (self.rootpass), 'employees'])

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        print "  testing InnoDB..."
        self._test_database()


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
        pass

class ServerMySQLTestsuite(testlib.TestlibCase):
    '''MySQL testsuite exerciser

       This is mostly based on the test-bt target from the (unpackaged)
       makefile in the MySQL testsuite. It is more extensive than the
       set of tests that are run at package build time. It takes a long
       time to run, however (~2 hours on relatively modern hardware).'''

    def setUp(self):
        '''Setup methods'''
        self.testuser = 'mysql'
        p = pwd.getpwnam(self.testuser)
        self.uid = p[2]
        self.gid = p[3]

        # this should not be necessary but just to be paranoid
        try:
            os.mkdir('/var/tmp/mysql')
            os.chown('/var/tmp/mysql', self.uid, self.gid)
        except OSError:
            pass

        self.tmpvardir = mkdtemp(prefix="mysql-var-", dir='/var/tmp/mysql')
        self.tmprundir = mkdtemp(prefix="mysql-tmp-", dir='/var/tmp/mysql')
        os.chown(self.tmpvardir, self.uid, self.gid)
        os.chown(self.tmprundir, self.uid, self.gid)

        self.mydir = os.getcwd()
        os.chdir("/usr/lib/mysql-testsuite")

    def tearDown(self):
        '''Shutdown methods'''
        os.chdir(self.mydir)
        shutil.rmtree(self.tmpvardir)
        shutil.rmtree(self.tmprundir)

    def run_cmd(self, args):
        cmd = ['sudo', '-u', self.testuser, './mysql-test-run.pl', '--force', '--vardir=' + self.tmpvardir, '--tmpdir=' + self.tmprundir]
        cmd.extend(args)

        return testlib.cmd(cmd)

    def test_bt_normal(self):
        '''(MySQL testsuite) normal tests'''
        (rc, report) = self.run_cmd(['--comment=normal', '--timer', '--skip-ndbcluster', '--report-features'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_bt_ps_protocol(self):
        '''(MySQL testsuite) ps protocol tests'''
        (rc, report) = self.run_cmd(['--comment=ps', '--timer', '--skip-ndbcluster', '--ps-protocol'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_bt_funcs1(self):
        '''(MySQL testsuite) funcs1 + ps tests'''
        (rc, report) = self.run_cmd(['--comment=funcs1+ps', '--suite=funcs_1', '--reorder', '--ps-protocol'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_bt_funcs2(self):
        '''(MySQL testsuite) funcs2 tests'''
        (rc, report) = self.run_cmd(['--comment=funcs2', '--suite=funcs_2'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_bt_partitions(self):
        '''(MySQL testsuite) partitions tests'''
        (rc, report) = self.run_cmd(['--comment=partitions', '--suite=parts'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_bt_stress(self):
        '''(MySQL testsuite) stress tests'''
        (rc, report) = self.run_cmd(['--comment=stress', '--suite=stress'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_bt_jp(self):
        '''(MySQL testsuite) jp tests'''
        (rc, report) = self.run_cmd(['--comment=jp', '--suite=jp'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    # nist suite doesn't appear to be included with the mysql distribution
    #
    #def test_bt_nist(self):
    #    '''(MySQL testsuite) nist tests'''
    #    (rc, report) = self.run_cmd(['--comment=nist', '--suite=nist'])
    #    expected = 0
    #    result = 'Got exit code %d, expected %d\n' % (rc, expected)
    #    self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    suite = unittest.TestSuite()

    initial_setup()
    # add tests here
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerGeneric))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerSimple))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerSSL))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerDataTest))

    if os.path.exists('/usr/lib/mysql-testsuite'):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerMySQLTestsuite))
    else:
        print "Skipping MySQL test suite (install mysql-testsuite package to enable)."

    # only use for debugging-- it doesn't cleanup
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerStub))

    # run tests
    rc = unittest.TextTestRunner(verbosity=2).run(suite)

    # make sure mysqld isn't running
    print "Killing stray mysqld processes"
    subprocess.call(['killall', 'mysqld'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # workaround for https://bugs.launchpad.net/ubuntu/+source/mysql-dfsg-5.0/+bug/105457
    subprocess.call(['killall', 'mysqld_safe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['killall', '-9', 'mysqld_safe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if not rc.wasSuccessful():
        sys.exit(1)
