#!/usr/bin/python
#
#    test-puppet.py quality assurance test script for puppet
#    Copyright (C) 2010-2014 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Author: Jamie Strandboge <jamie@canonical.com>
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
# packages required for test to run:
# QRT-Packages: puppet puppetmaster puppet-testsuite rake
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates:
# files and directories required for the test to run:
# QRT-Depends:
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'karmic':
        schroot -c karmic -u root -- sh -c 'apt-get -y install lsb-release puppet puppetmaster puppet-testsuite && ./test-puppet.py -v'

    TODO:
    - test a lot more puppet capabilities
    - fix 'Install RRD for metric reporting tests'. rrdtool and librrd-ruby1.8
      are not enough
    - Update puppet spec tests to prevent failures after the Ruby update for
      USN-1377-1. Known issues/fixes are:
      - https://projects.puppetlabs.com/issues/11996:
        - https://github.com/puppetlabs/puppet/pull/342/commits (2.6)
        - https://github.com/puppetlabs/puppet/pull/344/commits (2.7)
      - https://projects.puppetlabs.com/issues/12269:
        - https://github.com/puppetlabs/puppet/pull/425/commits (2.7)
      - https://projects.puppetlabs.com/issues/12454:
        - https://github.com/puppetlabs/puppet/pull/465/commits (master)
        - https://github.com/puppetlabs/puppet/commit/3d518b01681a7ddf934cbb6bb91f8cd56e2e8096

    INFO:
    - running individual tests:
      cd /usr/share/puppet-testsuite
      spec/...rb
      test/...rb

    NOTES:
    - gems change and that can affect the test suite. So on Oneiric there used
      to be rspec 2.6.0, but it was updated to 2.7.0 and the puppet testsuite
      broke. So the best thing to do is if you need to fetch a gem, specify
      the version that works best. Eg:
      $ sudo gem install rspec -v 2.6.0

      If you have installed newer gems, just do something like:
      $ for i in `gem list | grep '[a-z].*' | cut -d ' ' -f 1` ; do sudo gem uninstall $i ; done
      $ sudo gem install <gem you want> -v <version of gem>

    - Something changed in the ruby stack on 11.04 post-release that affected
      the puppet testsuite, which is why it has to disable 3 network/handler/*rb
      tests and has HttpPool errors.

    - Some of these tests may not pass if the system is overly loaded, such as
      when running these tests under concurrent VMs
'''

import unittest, subprocess, sys, os, time
import shutil
from stat import *
import tempfile
import testlib
import re

use_private = True
try:
    from private.qrt.puppet import PuppetPrivateTest
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class PuppetTest(testlib.TestlibCase):
    '''Test puppet.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

        self.plugindir =       "/etc/puppet/plugins"
        self.classesdir =      "/etc/puppet/manifests/classes"
        self.site_pp =         "/etc/puppet/manifests/site.pp"
        self.fileserver_conf = "/etc/puppet/fileserver.conf"
        self.debian_version =  "/etc/debian_version"
        self.hosts_file =      "/etc/hosts"
        self.puppet_default =  "/etc/default/puppet"

        self.testsuite = "/usr/share/puppet-testsuite"
        self.testsuite_disabled = []
        self.testsuite_edits = []
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')

        # Create missing directories
        if not os.path.exists(self.plugindir):
            os.mkdir(self.plugindir)
        if not os.path.exists(self.classesdir):
            os.mkdir(self.classesdir)

        # Set up configuration file
        testlib.config_replace(self.fileserver_conf,'''#
[files]
  path /etc/puppet/files
  allow *

[plugins]
  path /etc/puppet/plugins
  allow *
''',append=False)

        # On Quantal+, we need to use mocha from gem since the one in
        # the archive is too new. Rename a few directories. There's
        # probably a better way of doing this.
        if self.lsb_release['Release'] == 12.10 or self.lsb_release['Release'] == 13.04:
            rc, report = testlib.cmd(['mv', '/usr/lib/ruby/vendor_ruby/mocha',
                                      '/usr/lib/ruby/vendor_ruby/mocha-disabled'])
            expected = 0
            self.assertEquals(rc, expected, "directory rename failed:\n" + report)

            rc, report = testlib.cmd(['mv', '/usr/lib/ruby/vendor_ruby/mocha.rb',
                                      '/usr/lib/ruby/vendor_ruby/mocha.rb-disabled'])
            expected = 0
            self.assertEquals(rc, expected, "directory rename failed:\n" + report)

        # Enable the client service on lucid+
        testlib.config_replace(self.puppet_default, "", True)
        subprocess.call(['sed', '-i', 's/^START=no/START=yes/', self.puppet_default])

        # Add puppet host to host file
        testlib.config_replace(self.hosts_file, "127.0.0.1 puppet", True)

        self.serverdaemon = testlib.TestDaemon("/etc/init.d/puppetmaster")
        self.clientdaemon = testlib.TestDaemon("/etc/init.d/puppet")

        self._restart()

    def tearDown(self):
        '''Clean up after each test_* function'''

        self._stop()
        testlib.config_restore(self.fileserver_conf)
        testlib.config_restore(self.site_pp)
        testlib.config_restore(self.hosts_file)
        testlib.config_restore(self.puppet_default)

        if os.path.exists(self.classesdir):
            testlib.recursive_rm(self.classesdir)

        if os.path.exists(self.plugindir):
            testlib.recursive_rm(self.plugindir)

        for i in self.testsuite_disabled:
            f = os.path.join(self.tmpdir, i)
            if os.path.exists(f):
                shutil.copy(f, os.path.join(self.testsuite, i))

        for i in self.testsuite_edits:
            testlib.config_restore(i)

        # Rename deb mocha directories back
        if self.lsb_release['Release'] == 12.10 or self.lsb_release['Release'] == 13.04:
            rc, report = testlib.cmd(['mv', '/usr/lib/ruby/vendor_ruby/mocha-disabled',
                                      '/usr/lib/ruby/vendor_ruby/mocha'])
            expected = 0
            self.assertEquals(rc, expected, "directory rename failed:\n" + report)

            rc, report = testlib.cmd(['mv', '/usr/lib/ruby/vendor_ruby/mocha.rb-disabled',
                                      '/usr/lib/ruby/vendor_ruby/mocha.rb'])
            expected = 0
            self.assertEquals(rc, expected, "directory rename failed:\n" + report)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        # Make sure /etc/debian_version file permissions are back to default
        os.chmod(self.debian_version,0644)

    def _start(self):
        '''Start daemons'''
        rc, result = self.serverdaemon.start()
        self.assertTrue(rc, result)

        # Give server some time to start
        time.sleep(1)

        rc, result = self.clientdaemon.start()
        self.assertTrue(rc, result)

    def _stop(self):
        '''Stop daemons'''
        rc, result = self.clientdaemon.stop()
        rc, result = self.serverdaemon.stop()
        time.sleep(2)

    def _restart(self):
        '''Shutdown and startup daemons'''
        self._stop()
        self._start()

    def test_permissions(self):
        '''Test resetting file permissions'''
        if self.lsb_release['Release'] >= 10.04:
            return self._skipped("Prefer puppet-testsuite in 10.04 and higher")

        testlib.config_replace(self.site_pp,'''#
import "classes/*"

node default {
    include debian_version
}
''',append=False)

        testlib.config_replace(os.path.join(self.classesdir, 'debian_version.pp'),'''#
class debian_version {
    file { "/etc/debian_version":
        owner => "root",
        group => "root",
        mode  => 644,
    }
}
''',append=False)

        # Muck up /etc/debian_version file permissions
        os.chmod(self.debian_version,0640)

        self._restart()

        # Give client some time to notice permissions are incorrect
        time.sleep(2)

        # Check permissions
        self.assertEquals(S_IMODE(os.stat(self.debian_version)[0]) & 0644, 420, "'%s' is not chmod 0644" % (self.debian_version))

    def _run_rake_tests(self, test_type, ex_failures, ex_errors=None, non_deterministic_tests=None, non_deterministic_errors=None):
        '''Helper for rake tests'''
        ts_dir = "/usr/share/puppet-testsuite"
        ts_dir_test = "/usr/share/puppet-testsuite/test"

        valid_test_types = ['spec']
        if self.lsb_release['Release'] > 99.10:
            valid_test_types.append('test') # this should (maybe?) be used in 2.7.3 and higher
        else:
            valid_test_types.append('unit')
        self.assertTrue(test_type in valid_test_types, "Invalid test type '%s'" % test_type)

        nd_tests = 0
        if non_deterministic_tests != None:
            nd_tests = len(non_deterministic_tests)

        nd_errors = 0
        if non_deterministic_errors != None:
            nd_errors = len(non_deterministic_errors)

        os.chdir(ts_dir)
        # Quantal and Raring now use ruby1.9 by default, make sure we use ruby1.8
        if self.lsb_release['Release'] == 12.10 or self.lsb_release['Release'] == 13.04:
            if test_type == 'unit':
                # Work around "rake" hardcoded in main testsuite Rakefile
                os.chdir(ts_dir_test)
                rc, report = testlib.cmd(['ruby1.8', '/usr/bin/rake'])
            else:
                rc, report = testlib.cmd(['ruby1.8', '/usr/bin/rake', test_type])
        else:
            rc, report = testlib.cmd(['rake', test_type])

        # skip rc check as these all fail. Instead, parse the rake output. Idea
        # here is that we check if we have no more failures. Then check if we
        # have all our expected failures. This could be made more intelligent,
        # but this at least guarantees we won't miss anything (even though it
        # does require updating the script of one of the expected failures
        # starts to work)
        pat = re.compile(r'^[0-9]+ .*, [0-9]+ failure')
        line = ''
        for line in report.splitlines():
            if pat.search(line) != None:
                break
        print "\nDEBUG: %s" % line

        num_failures = 0
        for part in line.split(', '):
            if "failure" in part:
                num_failures = int(part.split()[0])

        total_failures = len(ex_failures) + nd_tests
        self.assertTrue(num_failures <= total_failures,
                        "Found more than the '%d' expected failures (%d)\n" % (total_failures, num_failures) + report)

        for f in ex_failures:
            result = "Could not find '%s' in report" % (f)
            self.assertTrue(f in report, result + report)

        # unit tests also have errors
        if ex_errors == None:
            return

        num_errors = int(line.split(', ')[3].split()[0])

        total_errors = len(ex_errors) + nd_errors
        self.assertTrue(num_errors <= total_errors,
                        "Found more than the '%d' expected errors (%d)\n" % (total_errors, num_errors) + report)

        for f in ex_errors:
            result = "Could not find '%s' in report" % (f)
            self.assertTrue(f in report, result + report)

        if non_deterministic_tests == None:
            return

        for n in non_deterministic_tests:
            result = "INFO: found '%s' in report (test marked as non-deterministic)" % (n)
            if n in report:
                print result

        if non_deterministic_errors == None:
            return

        for n in non_deterministic_errors:
            result = "INFO: found '%s' in report (error marked as non-deterministic)" % (n)
            if n in report:
                print result

    def test_puppet_spec_tests(self):
        '''Testsuite rake spec (takes a while)'''

        if self.lsb_release['Release'] >= 11.04:
            (totalmem,totalswap) = testlib.get_memory()
            if totalmem < 1000000:
                print "\nWARNING: Need 1GB of RAM or higher on Natty+ or tests may fail!"

        ex_failures = []
        if self.lsb_release['Release'] == 10.04:
            #ex_failures.append("Errno::EISDIR in 'Puppet::Indirector::FileContent::FileServer when finding files should find plugin file content in the environment specified in the request'")
            ex_failures.append("Net::HTTPError in 'Puppet::Indirector::REST when using webrick when finding a model instance over REST when a matching model instance can be found should use a supported format'")
            ex_failures.append("Net::HTTPError in 'Puppet::Indirector::REST when using mongrel when finding a model instance over REST when a matching model instance can be found should use a supported format'")
            ex_failures.append("Puppet::ParseError in 'Puppet::Parser::Compiler should be able to determine the configuration version from a local version control repository'")
            ex_failures.append("'Puppet::Type::File when writing files should fail if no backup can be performed' FAILED")
            ex_failures.append("'puppetmasterd should create a PID file' FAILED")
            ex_failures.append("Puppet::SSLCertificates::Support::MissingCertificate in 'puppetmasterd should be serving status information over xmlrpc'")
        elif self.lsb_release['Release'] == 11.10:
            ex_failures.append("Puppet::Interface::Action with action-level options it should behave like things that declare options should support option documentation")
            ex_failures.append("Puppet::Application::Inspect when executing when archiving to a bucket when auditing files should not send unreadable files")
            ex_failures.append("Puppet::Interface it should behave like things that declare options should support option documentation")
            ex_failures.append("Puppet::Parser::Compiler should be able to determine the configuration version from a local version control repository")
        elif self.lsb_release['Release'] == 12.04:
            # Holy failures, Batman! Good thing this is an LTS!
            ex_failures.append("Puppet::Type::File#asuser should return the desired owner if they can write to the parent directory")
            ex_failures.append("Puppet::Type::File#asuser should return nil if the desired owner can't write to the parent directory")
            ex_failures.append("Puppet::Type::File#asuser should return the desired owner if they can write to the parent directory")
            ex_failures.append("Puppet::Type::File#asuser should return nil if the desired owner can't write to the parent directory")

            # CVE-2013-4969 regression fix has broken test cases
            ex_failures.append("Puppet::Type::File#write when resource mode is not supplied and content is supplied should default to 0644 mode")
            ex_failures.append("Puppet::Type::File#write when resource mode is not supplied and no content is supplied should use puppet's default umask of 022")

            ex_failures.append("Puppet::Application::Device when running for each device should cleanup the vardir setting after the run")
            ex_failures.append("Puppet::Application::Device when running for each device should cleanup the confdir setting after the run")
            ex_failures.append("Puppet::Application::Device when running for each device should cleanup the certname setting after the run")
            ex_failures.append("Puppet::Application::Inspect when executing when archiving to a bucket when auditing files should not send unreadable files")
            ex_failures.append("Puppet::Indirector::SslFile should fail if no store directory or file location has been set")
            ex_failures.append("Puppet::Parser::Compiler should be able to determine the configuration version from a local version control repository")
            # Big heap of fail: (not sure why it's running a windows test...)
            self.testsuite_disabled.append("spec/integration/util/windows/security_spec.rb")
            # This test should be removed, as the file it's testing got removed in 2.7.11-1ubuntu2.5
            self.testsuite_disabled.append("spec/unit/util/instrumentation/listeners/process_name_spec.rb")
        elif self.lsb_release['Release'] == 12.10 or self.lsb_release['Release'] == 13.04: # Quantal and Raring
            ex_failures.append("Puppet::Type::File#asuser should return the desired owner if they can write to the parent directory")
            ex_failures.append("Puppet::Type::File#asuser should return nil if the desired owner can't write to the parent directory")
            ex_failures.append("Puppet::Type::File#asuser should return the desired owner if they can write to the parent directory")
            ex_failures.append("Puppet::Type::File#asuser should return nil if the desired owner can't write to the parent directory")

            # CVE-2013-4969 regression fix has broken test cases
            ex_failures.append("Puppet::Type::File#write when resource mode is not supplied and content is supplied should default to 0644 mode")
            ex_failures.append("Puppet::Type::File#write when resource mode is not supplied and no content is supplied should use puppet's default umask of 022")

            ex_failures.append("Puppet::Application::Inspect when executing when archiving to a bucket when auditing files should not send unreadable files")
            ex_failures.append("Puppet::Node::Facts::InventoryActiveRecord#search should return node names that match 'equal' constraints")
            ex_failures.append("Puppet::Node::Facts::InventoryActiveRecord#search should return node names that match 'not equal' constraints")
            ex_failures.append("Puppet::Indirector::SslFile should fail if no store directory or file location has been set")
            ex_failures.append("Puppet::Parser::Compiler should be able to determine the configuration version from a local version control repository")
            ex_failures.append("Puppet::Network::RestAuthConfig should warn when matching against IP addresses")
            # Big heap of fail: (not sure why it's running a windows test...)
            self.testsuite_disabled.append("spec/integration/util/windows/security_spec.rb")
        elif self.lsb_release['Release'] >= 13.10: # Saucy and higher
            ex_failures.append("Puppet::Network::Server when using webrick before listening should not be reachable at the specified address and port")
            ex_failures.append("Puppet::Network::Server when using webrick when listening should be reachable on the specified address and port")
            ex_failures.append("Puppet::Network::Server when using webrick when listening should use any specified bind address")
            ex_failures.append("Puppet::Network::Server when using webrick when listening should not allow multiple servers to listen on the same address and port")
            ex_failures.append("Puppet::Network::Server when using webrick after unlistening should not be reachable on the port and address assigned")
            ex_failures.append("Puppet::Parser::Compiler using classic parser behaves like the compiler should be able to determine the configuration version from a local version control repository")
            ex_failures.append("Puppet::Parser::Compiler using future parser behaves like the compiler should be able to determine the configuration version from a local version control repository")
            ex_failures.append("Puppet::SSL::CertificateAuthority should create a CA host")
            ex_failures.append("Puppet::SSL::CertificateAuthority should be able to generate a certificate")
            ex_failures.append("Puppet::SSL::CertificateAuthority should be able to generate a new host certificate")
            ex_failures.append("Puppet::SSL::CertificateAuthority should be able to revoke a host certificate")
            ex_failures.append("Puppet::SSL::CertificateAuthority should have a CRL")
            ex_failures.append("Puppet::SSL::CertificateAuthority should be able to read in a previously created CRL")
            ex_failures.append("Puppet::SSL::CertificateAuthority when signing certificates should be able to sign certificates")
            ex_failures.append("Puppet::SSL::CertificateAuthority when signing certificates should save the signed certificate")
            ex_failures.append("Puppet::SSL::CertificateAuthority when signing certificates should be able to sign multiple certificates")
            ex_failures.append("Puppet::SSL::CertificateAuthority when signing certificates should save the signed certificate to the :signeddir")
            ex_failures.append("Puppet::SSL::CertificateAuthority when signing certificates should save valid certificates")
            ex_failures.append("Puppet::SSL::CertificateAuthority when signing certificates should verify proof of possession when signing certificates")
            ex_failures.append("Puppet::SSL::CertificateRequest should be able to save CSRs")
            ex_failures.append("Puppet::SSL::CertificateRequest should be able to find saved certificate requests via the Indirector")
            ex_failures.append("Puppet::SSL::CertificateRequest should save the completely CSR when saving")
            ex_failures.append("Puppet::SSL::CertificateRevocationList should be able to read in written out CRLs with no revoked certificates")
            ex_failures.append("Puppet::SSL::Host should be considered a CA host if its name is equal to 'ca'")
            ex_failures.append("Puppet::SSL::Host should pass the verification of its own SSL store")
            ex_failures.append("Puppet::SSL::Host when managing its key should be able to generate and save a key")
            ex_failures.append("Puppet::SSL::Host when managing its key should save the key such that the Indirector can find it")
            ex_failures.append("Puppet::SSL::Host when managing its key should save the private key into the :privatekeydir")
            ex_failures.append("Puppet::SSL::Host when managing its certificate request should be able to generate and save a certificate request")
            ex_failures.append("Puppet::SSL::Host when managing its certificate request should save the certificate request such that the Indirector can find it")
            ex_failures.append("Puppet::SSL::Host when managing its certificate request should save the private certificate request into the :privatekeydir")
            ex_failures.append("Puppet::SSL::Host when the CA host should never store its key in the :privatekeydir")
            ex_failures.append("Puppet::Application::Inspect when executing when archiving to a bucket when auditing files should not send unreadable files")
            ex_failures.append("Puppet::Application::Master when running the main command should give the server to the daemon")
            ex_failures.append("Puppet::Application::Master when running the main command should generate a SSL cert for localhost")
            ex_failures.append("Puppet::Application::Master when running the main command should make sure to *only* hit the CA for data")
            ex_failures.append("Puppet::Application::Master when running the main command should daemonize if needed")
            ex_failures.append("Puppet::Application::Master when running the main command should start the service")
            ex_failures.append("Puppet::Reports::Rrdgraph should not error on 0.25.x report format")
            ex_failures.append("Puppet::Reports::Rrdgraph should not error on 2.6.x report format")

            # Big heap of fail: (not sure why it's running a windows test...)
            self.testsuite_disabled.append("spec/integration/util/windows/security_spec.rb")
            # This fails miserably, need to figure out why
            self.testsuite_disabled.append("spec/integration/faces/ca_spec.rb")

        if self.lsb_release['Release'] == 11.10 or self.lsb_release['Release'] == 12.04:
            print "INFO: installing rspec from gem since we need 2.6.0 to run 'rake spec' with puppet 2.7"
            # rspec 2.7 doesn't work with ruby1.8 on 11.10
            rc, report = testlib.cmd(['gem', 'install', 'rspec', '-v', '2.6.0'])
            expected = 0
            self.assertEquals(rc, expected, "get install rspec failed:\n" + report)

        if self.lsb_release['Release'] == 12.10 or self.lsb_release['Release'] == 13.04:
            print "INFO: installing mocha from gem since we need an older version in quantal+"
            # mocha 0.10.x doesn't work with puppet 2.7
            rc, report = testlib.cmd(['gem1.8', 'install', 'mocha', '-v', '0.9.12'])
            expected = 0
            self.assertEquals(rc, expected, "get install mocha failed:\n" + report)

        if self.lsb_release['Release'] >= 13.10:
            print "INFO: installing rgen from gem since it's not packaged"
            # rgen is needed to run test suite on 13.10+
            rc, report = testlib.cmd(['gem', 'install', 'rgen', '-v', '0.6.6'])
            expected = 0
            self.assertEquals(rc, expected, "get install rgen failed:\n" + report)

        non_deterministic_tests = []
        if self.lsb_release['Release'] == 10.04:
            non_deterministic_tests.append("'Puppet::Type::Mount::ProviderParsed Puppet::Type::Mount::ProviderParsed when modifying the filesystem tab should write the mount to disk when :flush is called' FAILED")
        if self.lsb_release['Release'] == 12.04:
            # New failure with July 2012 security update:
            non_deterministic_tests.append("Puppet::Network::RestAuthConfig should warn when matching against IP addresses")
        if self.lsb_release['Release'] == 12.10:
            non_deterministic_tests.append("Puppet::Indirector::REST when making http requests should provide a suggestive error message when certificate verify failed")
        if self.lsb_release['Release'] >= 12.10:
            # These three only fail on i386 for some reason
            non_deterministic_tests.append("Puppet::Type::Exec::ProviderPosix#run should execute the command if the command given includes arguments or subcommands")
            non_deterministic_tests.append("Puppet::Type::Exec::ProviderPosix#run should warn if you're overriding something in environment")
            non_deterministic_tests.append("Puppet::Type::Exec::ProviderPosix#run when the command is a relative path should execute the command if it finds it in the path and is executable")

        for i in self.testsuite_disabled:
            d = os.path.dirname(os.path.join(self.tmpdir, i))
            if not os.path.exists(d):
                testlib.cmd(['mkdir', '-p', d])
            shutil.move(os.path.join(self.testsuite, i), os.path.join(self.tmpdir, i))

        if self.lsb_release['Release'] >= 12.10:
            # Disable the gem check since we want to use the system rspec
            f = os.path.join(self.testsuite, "spec/spec_helper.rb")
            self.testsuite_edits.append(f)
            testlib.config_replace(f, "", append=True)
            subprocess.call(['sed', '-i', "s/^gem 'rspec'/#gem 'rspec'/", f])

        self._run_rake_tests('spec', ex_failures, None, non_deterministic_tests)

    def test_puppet_unit_tests(self):
        '''Testsuite rake unit (takes a while)'''

        # Seems there is no unit tests anymore on saucy+
        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("No unit tests in 13.10 and later")

        if self.lsb_release['Release'] >= 11.10:
            (totalmem,totalswap) = testlib.get_memory()
            if totalmem < 1000000:
                print "\nWARNING: Need 1GB of RAM or higher on Oneiric+ or tests may fail!"

        ex_failures = []
        if self.lsb_release['Release'] == 10.04:
            ex_failures.append("test_uppercase_files_are_renamed_and_read(TestCertSupport)")
            ex_failures.append("test_file_rc(TestDebianServiceProvider)")
            ex_failures.append("test_sysv_rc(TestDebianServiceProvider)")
            ex_failures.append("test_autorequire_user(TestExec)")
            ex_failures.append("test_wxrubylayouts_gem(TestPackageProvider)")
            ex_failures.append("test_execution(TestPuppetModule)")
            ex_failures.append("test_existence(TestPuppetModule)")
        elif self.lsb_release['Release'] == 11.10:
            ex_failures.append("test_autorequire_user(TestExec)")
            ex_failures.append("test_nofollowlinks(TestFile)")
            ex_failures.append("test_duplicateIDs(TestGroupProvider)")
            ex_failures.append("test_mkgroup(TestGroupProvider)")
            ex_failures.append("test_wxrubylayouts_gem(TestPackageProvider)")
            ex_failures.append("test_alluserproperties(TestUserProvider)")
            ex_failures.append("test_infocollection(TestUserProvider)")
            ex_failures.append("test_simpleuser(TestUserProvider)")
        elif self.lsb_release['Release'] == 12.04:
            ex_failures.append("test_autorequire_user(TestExec)")
            ex_failures.append("test_nofollowlinks(TestFile)")
            ex_failures.append("test_duplicateIDs(TestGroupProvider)")
            ex_failures.append("test_mkgroup(TestGroupProvider)")
            ex_failures.append("test_wxrubylayouts_gem(TestPackageProvider)")
            ex_failures.append("test_30_stale_lock(TestPuppetUtilPidlock)")
            ex_failures.append("test_alluserproperties(TestUserProvider)")
            ex_failures.append("test_infocollection(TestUserProvider)")
            ex_failures.append("test_simpleuser(TestUserProvider)")
        else: # Quantal and higher
            ex_failures.append("test_autorequire_user(TestExec)")
            ex_failures.append("test_nofollowlinks(TestFile)")
            ex_failures.append("test_duplicateIDs(TestGroupProvider)")
            ex_failures.append("test_mkgroup(TestGroupProvider)")
            ex_failures.append("test_wxrubylayouts_gem(TestPackageProvider)")
            ex_failures.append("test_alluserproperties(TestUserProvider)")
            ex_failures.append("test_infocollection(TestUserProvider)")
            ex_failures.append("test_simpleuser(TestUserProvider)")


        # Disabling this test also requires updating test/ral/type/filesources.rb, so
        # do it here
        if self.lsb_release['Release'] >= 11.04 and self.lsb_release['Release'] < 13.10:
            self.testsuite_disabled.append("test/network/handler/runner.rb")

            # Need to include puppet/network/http_pool since we lost runner.rb
            f = os.path.join(self.testsuite, "test/ral/type/filesources.rb")
            self.testsuite_edits.append(f)
            testlib.config_replace(f, "", append=True)
            subprocess.call(['sed', '-i', "s#^require 'mocha'#require 'mocha'\\nrequire 'puppet/network/http_pool'#", f])

        non_deterministic_tests = []
        if self.lsb_release['Release'] == 10.04:
            non_deterministic_tests.append("test_parse_line(TestCronParsedProvider)")
            non_deterministic_tests.append("test_wxrubylayouts_gem(TestPackageProvider)")
            non_deterministic_tests.append("'Puppet::Type::File when writing files should fail if no backup can be performed' FAILED")

        ex_errors = []
        ex_errors.append("RuntimeError: Global resource removal is deprecated")
        ex_errors.append("Puppet::Util::Settings::FileSetting::SettingError: Internal error: The :group setting for  must be 'service', not 'daemon'")
        ex_errors.append("Puppet::Util::Settings::FileSetting::SettingError: Internal error: The :group setting for  must be 'service', not 'daemon'")
        if self.lsb_release['Release'] == 11.10:
            ex_errors.append("MissingSourceFile: no such file to load -- sqlite3")
            ex_errors.append("MissingSourceFile: no such file to load -- sqlite3")
        if self.lsb_release['Release'] >= 11.10:
            ex_errors.append("NoMethodError: undefined method `system?' for #")

        non_deterministic_errors = []
        # This now fails on natty too with the july 2012 security update.
        # It used to only fail on Oneiric+
        if self.lsb_release['Release'] >= 11.04:
            non_deterministic_errors.append("Errno::ENOENT: No such file or directory - /tmp/puppettesting")

        test_type = 'unit'
        if self.lsb_release['Release'] > 99.10:
            test_type = 'test' # this should (maybe?) be used in 2.7.3 and higher

        for i in self.testsuite_disabled:
            d = os.path.dirname(os.path.join(self.tmpdir, i))
            if not os.path.exists(d):
                testlib.cmd(['mkdir', '-p', d])
            shutil.move(os.path.join(self.testsuite, i), os.path.join(self.tmpdir, i))

        self._run_rake_tests(test_type, ex_failures, ex_errors, non_deterministic_tests, non_deterministic_errors)


if __name__ == '__main__':
    if testlib.is_running_in_vm():
        print "INFO: some tests may fail under high machine load (ie, concurrent VMs)"

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PuppetTest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PuppetPrivateTest))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
