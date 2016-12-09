#!/usr/bin/python
#
#    test-postgresql.py quality assurance test script for postgresql
#    Copyright (C) 2009-2014 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# For checkbox:
# QRT-Packages: sudo postgresql postgresql-common libpq-dev procps hunspell-en-us language-pack-ru ssl-cert locales python-pygresql postgresql-plpython-8.4 postgresql-plperl-8.4 postgresql-pltcl-8.4 postgresql-server-dev-8.4 patch
# QRT-Privilege: root
# QRT-Alternates:
# QRT-Depends:
#
# For humans:
##--QRT-Packages-Common: sudo lsb-release postgresql-common libpq-dev procps language-pack-ru ssl-cert locales python-pygresql patch
##--QRT-Packages-8.4: postgresql-8.4 postgresql-plpython-8.4 postgresql-plperl-8.4 postgresql-pltcl-8.4 postgresql-server-dev-8.4 hunspell-en-us
##--QRT-Packages-9.1: postgresql-9.1 postgresql-plpython-9.1 postgresql-plperl-9.1 postgresql-pltcl-9.1 postgresql-server-dev-9.1 hunspell-en-us postgresql-plpython3-9.1 libecpg-dev
##--QRT-Packages-9.3: postgresql-9.3 postgresql-plpython-9.3 postgresql-plperl-9.3 postgresql-pltcl-9.3 postgresql-server-dev-9.3 hunspell-en-us postgresql-plpython3-9.3 libecpg-dev
#

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:

      sudo apt-get -y install sudo lsb-release postgresql-8.4 postgresql-common libpq-dev procps hunspell-en-us language-pack-ru ssl-cert locales python-pygresql postgresql-plpython-8.4 postgresql-plperl-8.4 postgresql-pltcl-8.4 postgresql-server-dev-8.4 patch && sudo ./test-postgresql.py -v

    Ubuntu has the following PostgreSQL versions:

      Ubuntu |	8.4	9.1	9.3
      -----------------------------
      14.04  |	 	 X*	 X
      13.10  |	 	 X
      12.10  |	 	 X
      12.04  |	 X*	 X
      10.04  |	 X

     * universe packages (have not been tested with this script)

    NOTES:
      - it may be required to remove postgresql and its databases if the tests
        are interrupted:
        $ sudo apt-get remove --purge postgresql*
        $ sudo rm -rf /var/lib/postgresql*
      - Tests expect the database to start up in a reasonable amount of time.
	As such, failures may occur if running tests in parallel on the same
        machine.
      - sets up the following locales: en_US, en_US.UTF-8 ru_RU, ru_RU.UTF-8
        en_US.UTF-8 and the system locale set to it (will need to update for
        Lucid/Karmic one the testsuite uses a different language)

    TODO:
      - remove Lucid/Karmic whitelisted failures once testsuite is updated to
        use a different language
      - slony
      - files in postgresql-contrib
      - pygresql tests should also use advanced.py, func.py and syscat.py from
        the tutorial in /usr/share/doc/python-pygresql/tutorial
'''

import unittest, subprocess, sys
import testlib
import os

try:
    from private.qrt.Postgresql import PrivatePostgresqlTest
except ImportError:
    class PrivatePostgresqlTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class PostgresqlTest(testlib.TestlibCase, PrivatePostgresqlTest):
    '''Test postgresql'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.ts_disabled_tests = []
        self.ts_loc = "/usr/share/postgresql-common"
        self.testuser = "testuser"
        self.testdb = "testdb"
        self.user = None

        self.daemon = None
        for i in [ '8.4' ]:
            p = '/etc/init.d/postgresql-%s' % (i)
            if os.path.exists(p):
                self.daemon = testlib.TestDaemon(p)
        if self.daemon == None:
            self.daemon = testlib.TestDaemon('/etc/init.d/postgresql')

        rc, result = self.daemon.start()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.user = None
        if len(self.ts_disabled_tests) > 0:
            os.chdir(self.ts_loc)
            for t in self.ts_disabled_tests:
                if not os.path.exists('./t/%s.disabled' % t):
                    continue
                subprocess.call(['mv', '-f', './t/%s.disabled' % t, './t/%s' % t])

        self.pgcnx = None
        testlib.cmd(['sudo', '-u', 'postgres', 'dropdb', self.testdb])
        testlib.cmd(['sudo', '-u', 'postgres', 'dropuser', self.testuser])

        rc, result = self.daemon.stop()

    def _pypg_word_find(self, query, content, invert=False):
        '''Check for a specific string'''
        warning = 'query is None\n'
        self.assertFalse(query is None, warning)

        q = query.getresult()
        warning = 'query result is None\n'
        self.assertFalse(q is None, warning)

        warning = 'Could not find "%s"\n' % content
        self.assertTrue(len(q) > 0, warning)

        found = False
        for i in q:
            res = "|".join([str(x) for x in i])
            if content in res:
                found = True
                break

        if invert:
            warning = 'Found "%s"\n' % content
            self.assertFalse(found, warning + str(q))
        else:
            warning = 'Could not find "%s"\n' % content
            self.assertTrue(found, warning + str(q))

    def _setup_locales(self):
        '''Setup required locales'''
        # these are needed for the tests
        locales = ['en_US', 'ru_RU']
        locales += ['en_US.utf8', 'ru_RU.utf8']

        for l in locales:
            (rc, report) = testlib.cmd(['locale-gen', l])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['locale-gen'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.environ.setdefault('LANG', 'en_US.utf8')
        os.environ['LANG'] = 'en_US.utf8'

        (rc, report) = testlib.cmd(['sh', '-c', 'locale'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        loc = "en_US.utf8"

        result = 'Could not find "LANG=%s"\n' % (loc)
        self.assertTrue("LANG=%s" % (loc) in report, result + report)

    def _create_user(self, username, password=None):
        '''Create a user'''
        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'createuser', '-DRS', username])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'psql', '-c', '\du'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ['List of roles', username]:
            result = "Could not find '%s' in report\n" % (search)
            self.assertTrue(search in report, result + report)

        if password:
            (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'psql', '-c', 'ALTER USER \"%s\" WITH PASSWORD \'%s\';' % (username, password)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue('ALTER ROLE' in report, "Could not find 'ALTER ROLE' in report\n" + report)

    def _drop_user(self, username):
        '''Create a user'''
        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'dropuser', username])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'psql', '-c', '\du'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = username
        result = "Could not find '%s' in report\n" % (search)
        self.assertFalse(search in report, result + report)

    def _create_db(self, dbname, username):
        '''Create a db'''
        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'createdb', '-O', username, dbname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'psql', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ['List of databases', dbname]:
            result = "Could not find '%s' in report\n" % (search)
            self.assertTrue(search in report, result + report)

    def _drop_db(self, dbname):
        '''Create a db'''
        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'dropdb', dbname])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'psql', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = dbname
        result = "Found '%s' in report\n" % (search)
        self.assertFalse(search in report, result + report)

    # test suite should be first
    def test_aa_testsuite(self):
        '''Testsuite'''
        print "\n Setting up locales"
        self._setup_locales()

        os.chdir(self.ts_loc)

        # Disable entire test scripts (useful for debugging)
        #self.ts_disabled_tests.append('001_packages.t')
        #self.ts_disabled_tests.append('002_existing_clusters.t')
        #self.ts_disabled_tests.append('005_PgCommon.t')
        #self.ts_disabled_tests.append('010_defaultport_cluster.t')
        #self.ts_disabled_tests.append('020_create_sql_remove.t')
        #self.ts_disabled_tests.append('030_errors.t')
        #self.ts_disabled_tests.append('040_upgrade.t')
        #self.ts_disabled_tests.append('041_upgrade_custompaths.t')
        #self.ts_disabled_tests.append('042_upgrade_tablespaces.t')
        #self.ts_disabled_tests.append('050_encodings.t')
        #self.ts_disabled_tests.append('051_inconsistent_encoding_upgrade.t')
        #self.ts_disabled_tests.append('052_upgrade_encodings.t')
        #self.ts_disabled_tests.append('060_obsolete_confparams.t')
        #self.ts_disabled_tests.append('070_non_postgres_clusters.t')
        #self.ts_disabled_tests.append('080_start.conf.t')
        #self.ts_disabled_tests.append('085_pg_ctl.conf.t')
        #self.ts_disabled_tests.append('090_multicluster.t')
        #self.ts_disabled_tests.append('100_upgrade_scripts.t')
        #self.ts_disabled_tests.append('110_integrate_cluster.t')
        #self.ts_disabled_tests.append('120_pg_upgradecluster_scripts.t')
        #self.ts_disabled_tests.append('130_nonroot_admin.t')
        #self.ts_disabled_tests.append('140_pg_config.t')
        #self.ts_disabled_tests.append('150_tsearch_stemming.t')

        # Known failures for specific test cases
        failed_ok = []

        # TODO: 8.4.1 lost the Russian translations-- update after the testsuite is updated
        if self.lsb_release['Release'] >= 9.10:
            failed_ok.append('not ok 18 - Server error message has correct language and encoding')
            failed_ok.append('not ok 39 - Server error message has correct language and encoding')

        if self.lsb_release['Release'] >= 10.04:
	    # these snuck into Lucid, likely because of locales are called
            # .utf8 now instead of .UTF-8
            failed_ok.append('not ok 87 - starting cluster as postgres fails without a log file')
            failed_ok.append('not ok 88 - starting cluster as root work without a log file')
            failed_ok.append('not ok 8 - system has a default UTF-8 locale')

        if self.lsb_release['Release'] == 12.04:
            # Busted
            self.ts_disabled_tests.append('180_ecpg.t')

        # Disable tests and have pretty output
        if len(self.ts_disabled_tests) > 0:
            print " Disabled tests:"
            for t in self.ts_disabled_tests:
                if not os.path.exists('./t/%s' % t):
                    continue
                print "  %s" % t
                subprocess.call(['mv', '-f', './t/%s' % t, './t/%s.disabled' % t])

        print " Enabled tests:"
        files = os.listdir('./t')
        files.sort()
        for t in files:
            if t.endswith(".t"):
                print "  %s" % t
        print " Running testsuite (this will take a while)..."

        # Use '+e' so we see all the failures
        (rc, report) = testlib.cmd(['sh', '+e', './testsuite'])
        pruned_report = report

        # Make a failure summary:
	# - show the test
        # - show the failure message
        # - show the ignored failures (and how many times ignored)
        summary = ''
        search = 'not ok'
        pruned_report = ''
        if search in report:
            summary = '\n\nFailure Summary:\n'
            found_failed_ok = dict()
            for line in report.splitlines():
                if line.startswith('==='):
                    summary += line + '\n'
                elif line.startswith(search):
                    if line not in failed_ok:
                        summary += line + '\n'
                elif line.startswith("Looks like you failed"):
                    summary += line + '\n'

                if line in failed_ok:
                    if found_failed_ok.has_key(line):
                        found_failed_ok[line] += 1
                    else:
                        found_failed_ok[line] = 1
                else:
                    pruned_report += line + '\n'

            summary += '\nIgnored fails:\n'
            for key in found_failed_ok.keys():
                summary += "%s: (%d)\n" % (key, found_failed_ok[key])
        else:
            pruned_report = report
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report + summary)

        result = "Found '%s' in report\n" % (search)
        self.assertFalse(search in pruned_report, result + report + summary)

    def test_basic_install(self):
        '''Test basic install'''
        # taken from http://testcases.qa.ubuntu.com/Install/ServerWhole

        self.user = testlib.TestUser()
        self.testuser = self.user.login
        self.testdb = "%s_db" % (self.testuser)

        print ""
        print " List databases"
        (rc, report) = testlib.cmd(['sudo', '-u', 'postgres', 'psql', '-l'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ['List of databases', 'template0']:
            result = "Could not find '%s' in report\n" % (search)
            self.assertTrue(search in report, result + report)

        print " Create user"
        self._create_user(self.testuser)

        print " Create database"
        self._create_db(self.testdb, self.testuser)

        print " Connect to database as user"
        (rc, report) = testlib.cmd(['sudo', '-u', self.testuser, 'psql', '-d', self.testdb, '-c', '\du'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ['List of roles', self.testuser]:
            result = "Could not find '%s' in report\n" % (search)
            self.assertTrue(search in report, result + report)

    def test_add_user(self):
        '''Test add/remove user'''
        self._create_user(self.testuser)
        self._drop_user(self.testuser)

    def test_add_db(self):
        '''Test add/remove database'''
        self._create_user(self.testuser)
        self._create_db(self.testdb, self.testuser)
        self._drop_db(self.testdb)
        self._drop_user(self.testuser)

    def test_pygresql(self):
        '''Test pygresql (basic)'''
        self.user = testlib.TestUser()
        self.testuser = self.user.login
        self.testdb = "pygresql_db"
        self._create_user(self.testuser, self.user.password)
        self._create_db(self.testdb, self.testuser)

        # From /usr/share/doc/pygresql/tutorial/basics.py
        import pg
        self.pgcnx = pg.connect(dbname=self.testdb, host='127.0.0.1', user=self.testuser, passwd=self.user.password)

        # create table
        self.pgcnx.query("""CREATE TABLE weather (city varchar(80), temp_lo int, temp_hi int, prcp float8, date date)""")
        self.pgcnx.query("""CREATE TABLE cities (name varchar(80), location point)""")

        # insert data
        self.pgcnx.query("""INSERT INTO weather VALUES ('San Francisco', 46, 50, 0.25, '1994-11-27')""")
        self.pgcnx.query("""INSERT INTO cities VALUES ('San Francisco', '(-194.0, 53.0)')""")
        self.pgcnx.query("INSERT INTO weather (date, city, temp_hi, temp_lo) VALUES ('1994-11-29', 'Hayward', 54, 37)")

        # select1
        q = self.pgcnx.query("SELECT * FROM weather")
        self._pypg_word_find(q, "Hayward")
        self._pypg_word_find(q, "San Francisco")

        q = self.pgcnx.query("""SELECT city, (temp_hi+temp_lo)/2 AS temp_avg, date FROM weather""")
        self._pypg_word_find(q, "San Francisco|48")
        self._pypg_word_find(q, "Hayward|45")
        q = self.pgcnx.query("""SELECT * FROM weather WHERE city = 'San Francisco' AND prcp > 0.0""")
        self._pypg_word_find(q, "San Francisco")
        q = self.pgcnx.query("SELECT DISTINCT city FROM weather ORDER BY city")
        self._pypg_word_find(q, "Hayward")
        self._pypg_word_find(q, "San Francisco")

        # select2
        q = self.pgcnx.query("""SELECT * INTO TABLE temptab FROM weather WHERE city = 'San Francisco' and prcp > 0.0""")
        q = self.pgcnx.query("SELECT * from temptab")
        self._pypg_word_find(q, "San Francisco|46|50|0.25|1994-11-27")

        # aggregate
	q = self.pgcnx.query("SELECT max(temp_lo) FROM weather")
        self._pypg_word_find(q, "46")
        q = self.pgcnx.query( """SELECT city, max(temp_lo) FROM weather GROUP BY city""")
        self._pypg_word_find(q, "San Francisco|46")
        self._pypg_word_find(q, "Hayward|37")

        # join
        q = self.pgcnx.query("""SELECT W1.city, W1.temp_lo, W1.temp_hi, W2.city, W2.temp_lo, W2.temp_hi FROM weather W1, weather W2 WHERE W1.temp_lo < W2.temp_lo and W1.temp_hi > W2.temp_hi""")
        self._pypg_word_find(q, "Hayward|37|54|San Francisco|46|50")
        q = self.pgcnx.query("""SELECT city, location, prcp, date FROM weather, cities WHERE name = city""")
        self._pypg_word_find(q, "San Francisco|(-194,53)|0.25|1994-11-27")
        q = self.pgcnx.query("""SELECT w.city, c.location, w.prcp, w.date FROM weather w, cities c WHERE c.name = w.city""")
        self._pypg_word_find(q, "San Francisco|(-194,53)|0.25|1994-11-27")

        # update
        self.pgcnx.query("""UPDATE weather SET temp_hi = temp_hi - 2,  temp_lo = temp_lo - 2 WHERE date > '1994-11-28'""")
        q = self.pgcnx.query("SELECT * from weather")
        self._pypg_word_find(q, "San Francisco|46|50|0.25|1994-11-27")
        self._pypg_word_find(q, "Hayward|35|52|None|1994-11-29")

        # delete
        self.pgcnx.query("DELETE FROM weather WHERE city = 'Hayward'")
        q = self.pgcnx.query("SELECT * from weather")
        self._pypg_word_find(q, "San Francisco|46|50|0.25|1994-11-27")
        self.pgcnx.query("DELETE FROM weather")
        q = self.pgcnx.query("SELECT * from weather")
        self.assertTrue(len(q.getresult()) == 0, "Found results after DELETE\n" + str(q.getresult()))

        # remove
        self.pgcnx.query("DROP TABLE weather, cities, temptab")
        for t in ['weather', 'cities', 'temptab']:
            try:
                q = self.pgcnx.query("SELECT * from %s" % t)
                self.assertTrue(False, "Found '%s' table after DELETE\n" % (t) + str(q.getresult()))
            except:
                pass

    def test_pygresql_escape_string(self):
        '''Test pygresql (escape strings)'''

        self.user = testlib.TestUser()
        self.testuser = self.user.login
        self.testdb = "pygresql_db"
        self._create_user(self.testuser, self.user.password)
        self._create_db(self.testdb, self.testuser)

        import pg
        self.pgcnx = pg.connect(dbname=self.testdb, host='127.0.0.1', user=self.testuser, passwd=self.user.password)

        search = "''"
        warning = 'Could not find "%s"\n' % search
        self.assertTrue(pg.escape_string("'") == search, warning)

        # fix for CVE-2009-2940 added this
        search = "''"
        warning = 'Could not find "%s"\n' % search
        try:
            self.assertTrue(self.pgcnx.escape_string("'") == search, warning)
        except AttributeError:
            warning = 'CVE-2009-2940: Could not find required pyobj.escape_string()'
            self.assertTrue(False, warning)

    def test_pygresql_escape_bytea(self):
        '''Test pygresql (escape bytea)'''
        if self.lsb_release['Release'] == 6.06:
            return self._skipped("functions don't exist in Dapper")

        self.user = testlib.TestUser()
        self.testuser = self.user.login
        self.testdb = "pygresql_db"
        self._create_user(self.testuser, self.user.password)
        self._create_db(self.testdb, self.testuser)

        import pg
        self.pgcnx = pg.connect(dbname=self.testdb, host='127.0.0.1', user=self.testuser, passwd=self.user.password)

        binary = file('/bin/ls','rb').read()
        escaped = pg.escape_bytea(binary)

        search = "Usage: "
        warning = 'Could not find "%s"\n' % search
        self.assertTrue(search in escaped, warning)

        search = "\\\\000"
        warning = 'Could not find "%s"\n' % search
        self.assertTrue(search in escaped, warning)

        # The following extra tests don't work on Oneiric+
        if self.lsb_release['Release'] >= 11.10:
            return

        # fix for CVE-2009-2940 added this
        try:
           escaped = self.pgcnx.escape_bytea(binary)
        except AttributeError:
            warning = 'CVE-2009-2940: Could not find required pyobj.escape_bytea()'
            self.assertTrue(False, warning)

        search = "Usage: "
        warning = 'Could not find "%s"\n' % search
        self.assertTrue(search in escaped, warning)

        search = "\\\\000"
        warning = 'Could not find "%s"\n' % search
        self.assertTrue(search in escaped, warning)

    # CVE tests should be last
    def test_zz_CVE_2010_0442(self):
        '''Test CVE-2010-0442'''
        self.user = testlib.TestUser()
        self.testuser = self.user.login
        self.testdb = "%s_db" % (self.testuser)
        self._create_user(self.testuser, self.user.password)
        self._create_db(self.testdb, self.testuser)

        import pg
        self.pgcnx = pg.connect(dbname=self.testdb, host='127.0.0.1', user=self.testuser, passwd=self.user.password)

        rc, result = self.daemon.status()
        try:
            q = self.pgcnx.query("SELECT substring(B'10101010101010101010101010101010101010101010101',33,-15);")
        except:
             # Natty and older calculate the string length, and return a
             # result. Oneiric and newer actually error out if the length
             # is specified as negative.
             if self.lsb_release['Release'] < 11.10:
                 self.assertTrue(False, "SELECT returned with error (likely vulnerable)")
             else:
                 self.assertTrue(True, "SELECT should have returned an error!")

if __name__ == '__main__':
    # simple
    unittest.main()
