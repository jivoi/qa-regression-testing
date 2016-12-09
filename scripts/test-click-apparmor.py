#!/usr/bin/python
#
#    test-click-apparmor.py quality assurance test script for click-apparmor
#    Copyright (C) 2013-2015 Canonical Ltd.
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
# QRT-Packages: click-apparmor
# QRT-Alternates:
# QRT-Depends:
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-<script>.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-<script>.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-<script>.tar.gz
    # cd /tmp/qrt-test-<script> ; ./install-packages ./test-<script>.py
    # ./test-<script>.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-<script.py>

    ### TODO: update for ./install-packages step ###
    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install lsb-release <QRT-Packages> && ./test-PKG.py -v'
'''


import unittest, sys, os
import errno
import glob
import tempfile
import testlib
import time

try:
    from private.qrt.ClickAppArmor import PrivateClickAppArmorTest
except ImportError:
    class PrivateClickAppArmorTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class ClickAppArmorTest(testlib.TestlibCase, PrivateClickAppArmorTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.apparmor_cache = "/var/cache/apparmor"
        self.apparmor_profiles = "/var/lib/apparmor/profiles"
        self.apparmor_clicks = "/var/lib/apparmor/clicks"

        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.environ['CLICK_DIR'] = self.tmpdir

        self.appname = "testlibmyapp"
        self.name = "com.ubuntu.developer.username.%s" % self.appname
        self.version = "0.1"
        self.fullname = "%s_%s_%s" % (self.name, self.appname, self.version)

        self.click_topdir = os.path.join(self.tmpdir, self.name, self.version)

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

        files = [os.path.join(self.apparmor_clicks, "%s.json" % self.fullname),
                 os.path.join(self.apparmor_profiles,
                              "click_%s" % self.fullname),
                 os.path.join(self.apparmor_cache,
                              "click_%s" % self.fullname)]

        try:
            with open("/sys/kernel/security/apparmor/.remove", 'w') as f:
                f.write(self.fullname)
        except (OSError, IOError) as e:
            if e.errno != errno.ENOENT:
                raise


        for fn in files:
            if os.path.lexists(fn):
                os.unlink(fn)

    def _click_install(self):
        '''Emulate enough of click install for us to run'''
        os.makedirs(os.path.join(self.click_topdir, "apparmor"))
        os.makedirs(os.path.join(self.click_topdir, ".click", "info"))

        self.click_sec_json_fn = os.path.join(self.click_topdir, "apparmor",
                                              "%s.json" % self.appname)
        self.click_sec_json = '''{
  "policy_groups": [
     "networking"
   ],
   "policy_version": 1.0
}
'''
        testlib.create_fill(self.click_sec_json_fn, self.click_sec_json)

        self.click_manifest_fn = os.path.join(self.click_topdir,
                                              ".click/info/%s.manifest" %
                                              (self.name))
        self.click_manifest = '''{
  "name": "%s",
  "version": "%s",
  "maintainer": "Foo Bar <foo.bar@example.com>",
  "title": "TestLibMyApp",
  "framework": "ubuntu-sdk-13.10",
  "hooks": {
    "%s": {
      "apparmor": "apparmor/%s.json",
      "desktop": "%s.desktop"
    }
  }
}
''' % (self.name, self.version, self.appname, self.appname, self.appname)
        testlib.create_fill(self.click_manifest_fn, self.click_manifest)
        self.click_sec_json_full_fn = os.path.join(self.apparmor_clicks,
                                                   "%s.json" % self.fullname)
        os.symlink(self.click_sec_json_fn, self.click_sec_json_full_fn)

    def _is_loaded(self, profile):
        '''Check if profile is loaded'''
        rc, report = testlib.cmd(['aa-status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if profile in report:
            return True
        return False

    def test_aa_clickhook_bad_version_in_sec_manifest(self):
        '''Test aa-clickhook skips with bad version in manifest'''
        self._click_install()
        self.click_sec_json_fn = os.path.join(self.click_topdir, "apparmor",
                                              "%s.json" % self.appname)
        contents = '''{
  "policy_groups": [
     "networking"
   ],
   "policy_version": 0.0
}
'''
        testlib.create_fill(self.click_sec_json_fn, contents)
        (rc, out) = testlib.cmd(['aa-clickhook'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))
        search = "ERROR: Invalid policy version for '%s" % self.fullname
        self.assertTrue(search in out, "Could not find '%s' in:\n%s" %
                        (search, out))

    def test_aa_clickhook_nonexistent_vendor_sec_manifest(self):
        '''Test aa-clickhook skips with non-existent vendor in manifest'''
        self._click_install()
        self.click_sec_json_fn = os.path.join(self.click_topdir, "apparmor",
                                              "%s.json" % self.appname)
        contents = '''{
  "policy_groups": [
     "networking"
   ],
   "policy_version": 1.0,
   "policy_vendor": "somevendor"
}
'''
        testlib.create_fill(self.click_sec_json_fn, contents)
        (rc, out) = testlib.cmd(['aa-clickhook'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))
        search = "ERROR: Could not generate AppArmor profile for '%s" % self.fullname
        self.assertTrue(search in out, "Could not find '%s' in:\n%s" %
                        (search, out))

    def test_aa_clickhook_malformed_sec_manifest(self):
        '''Test aa-clickhook skips with malformed security manifest'''
        self._click_install()
        self.click_sec_json_fn = os.path.join(self.click_topdir, "apparmor",
                                              "%s.json" % self.appname)
        contents = '''{
  "policy_groups": [
     "networking"
   ],
   "policy_version"
}
'''
        testlib.create_fill(self.click_sec_json_fn, contents)

        (rc, out) = testlib.cmd(['aa-clickhook'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))
        search = "ERROR: Could not parse click manifest. Skipping '%s.json'" % self.fullname
        self.assertTrue(search in out, "Could not find '%s' in:\n%s" %
                        (search, out))

    def test_aa_clicktool(self):
        '''Test aa-clicktool'''
        self._click_install()

        (rc, out) = testlib.cmd(['aa-clicktool', self.click_sec_json_full_fn])
        self.assertEquals(rc, 0, "aa-clicktool exited with error '%d':\n%s" %
                          (rc, out))

        search_terms = [self.fullname,
                        'policy_groups',
                        'networking',
                        '"policy_vendor": "ubuntu"',
                        '"policy_version":',
                        '"template":',
                        '"template_variables":',
                        '"APP_ID_DBUS": "com_2eubuntu_2edeveloper_2eusername_2etestlibmyapp_5ftestlibmyapp_5f0_2e1"',
                        '"APP_PKGNAME": "%s"' % self.name,
                        '"APP_VERSION": "0.1"',
                        '"CLICK_DIR": "{',
                       ]
        for search in search_terms:
            self.assertTrue(search in out, "Could not find '%s' in:\n%s" %
                            (search, out))

    def test_aa_clickhook_install(self):
        '''Test aa-clickhook (install)'''
        files = [os.path.join(self.apparmor_clicks, "%s.json" % self.fullname),
                 os.path.join(self.apparmor_profiles,
                              "click_%s" % self.fullname),
                 os.path.join(self.apparmor_cache,
                              "click_%s" % self.fullname)]

        for fn in files:
            self.assertFalse(os.path.lexists(fn), "Found '%s'" % fn)

        self._click_install()
        (rc, out) = testlib.cmd(['aa-clickhook'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))

        for fn in files:
            self.assertTrue(os.path.exists(fn), "Could not find '%s'" % fn)

        self.assertTrue(self._is_loaded(self.fullname), "'%s' is not loaded" %
                                                         self.fullname)

    def test_aa_clickhook_install_force(self):
        '''Test aa-clickhook (install --force)'''
        files = [os.path.join(self.apparmor_clicks, "%s.json" % self.fullname),
                 os.path.join(self.apparmor_profiles,
                              "click_%s" % self.fullname),
                 os.path.join(self.apparmor_cache,
                              "click_%s" % self.fullname)]

        for fn in files:
            self.assertFalse(os.path.lexists(fn), "Found '%s'" % fn)

        self._click_install()
        (rc, out) = testlib.cmd(['aa-clickhook', '-f'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))

        for fn in files:
            self.assertTrue(os.path.exists(fn), "Could not find '%s'" % fn)

        fn = os.path.join(self.apparmor_profiles, "click_%s" % self.fullname)
        with open(fn, 'r') as f:
            contents = f.read()
            f.close()
        for s in ['# injected via click hook', 'test-inject.include']:
            self.assertFalse(s in contents, "Found '%s' in:\n%s" % (
                             s, contents))

        self.assertTrue(self._is_loaded(self.fullname), "'%s' is not loaded" %
                                                         self.fullname)

    def test_aa_clickhook_install_force_with_include(self):
        '''Test aa-clickhook (install --force --include=...)'''
        files = [os.path.join(self.apparmor_clicks, "%s.json" % self.fullname),
                 os.path.join(self.apparmor_profiles,
                              "click_%s" % self.fullname),
                 os.path.join(self.apparmor_cache,
                              "click_%s" % self.fullname)]

        for fn in files:
            self.assertFalse(os.path.lexists(fn), "Found '%s'" % fn)

        self._click_install()

        include = os.path.join(self.tmpdir, "test-inject.include")
        rule = '/some/nonexistent/path r,'
        with open(include, "w+") as f:
            f.write('''%s\n''' % rule)
            f.close()

        (rc, out) = testlib.cmd(['aa-clickhook', '-f', '--include=%s' %
                                 include])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))

        for fn in files:
            self.assertTrue(os.path.exists(fn), "Could not find '%s'" % fn)

        fn = os.path.join(self.apparmor_profiles, "click_%s" % self.fullname)
        with open(fn, 'r') as f:
            contents = f.read()
            f.close()
        for s in ['# injected via click hook',
                  'test-inject.include']:
            self.assertTrue(s in contents, "Could not find '%s' in:\n%s" %
                            (s, contents))

        (rc, out) = testlib.cmd(['apparmor_parser', '-p', fn])
        self.assertEquals(rc, 0,
                          'apparmor_parser exited with error %d:\n%s' %
                          (rc, out))
        self.assertTrue(rule in out, "Could not find '%s' in;\n%s" % (rule,
                                                                      out))
        self.assertTrue(self._is_loaded(self.fullname), "'%s' is not loaded" %
                                                         self.fullname)

    def test_aa_clickhook_remove(self):
        '''Test aa-clickhook (remove)'''
        self._click_install()
        (rc, out) = testlib.cmd(['aa-clickhook'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))
        self.assertTrue(self._is_loaded(self.fullname), "'%s' is not loaded" %
                                        self.fullname)

        # Everything is installed now, lets simulate a click remove
        click_json = os.path.join(self.apparmor_clicks, "%s.json" %
                                                        self.fullname)
        files = [click_json,
                 os.path.join(self.apparmor_profiles,
                              "click_%s" % self.fullname)]

        os.unlink(click_json)
        (rc, out) = testlib.cmd(['aa-clickhook'])
        self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                          (rc, out))

        for fn in files:
            self.assertFalse(os.path.exists(fn), "Found '%s'" % fn)

        # aa-clickhook should not unload the profile at this time. Verify
        # that
        self.assertTrue(self._is_loaded(self.fullname), "'%s' is not loaded" %
                                                        self.fullname)

    def test_performance(self):
        '''Test click apparmor hook performance'''
        num = 50
        print("")
        print("Running hooks...")
        start = time.time()
        for i in range(1, num):
            self.version = "0.%d" % i
            self.fullname = "%s_%s_%s" % (self.name, self.appname,
                                          self.version)
            self.click_topdir = os.path.join(self.tmpdir, self.name,
                                             self.version)
            self._click_install()

            start_p = time.time()
            # (rc, out) = testlib.cmd(['aa-clickhook', '-f'])
            (rc, out) = testlib.cmd(['aa-clickhook'])
            self.assertEquals(rc, 0, "aa-clickhook exited with error '%d':\n%s" %
                              (rc, out))
            end_p = time.time()
            print("  %s %s took %.1f secs" % (self.appname, self.version,
                                              end_p - start_p))
        end = time.time()
        elapsed = end - start
        print("Elapsed = %.1f" % elapsed)
        print("Average = %.1f" % (elapsed / (num - 1)))

        # clean up
        print("Cleaning up...")
        for i in range(1, num):
            self.version = "0.%d" % i
            self.fullname = "%s_%s_%s" % (self.name, self.appname,
                                          self.version)
            files = [os.path.join(self.apparmor_clicks, "%s.json" %
                                  self.fullname),
                 os.path.join(self.apparmor_profiles,
                              "click_%s" % self.fullname),
                 os.path.join(self.apparmor_cache,
                              "click_%s" % self.fullname)]

            try:
                with open("/sys/kernel/security/apparmor/.remove", 'w') as f:
                    f.write(self.fullname)
            except (OSError, IOError) as e:
                if e.errno != errno.ENOENT:
                    raise

            for fn in files:
                if os.path.lexists(fn):
                    os.unlink(fn)


class ClickAppArmorTestsuite(testlib.TestlibCase):
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        self.topdir = os.getcwd()
        self.cached_src = os.path.join(self.topdir, "source")
        self.patch_system = None
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

    def test_testsuite(self):
        '''Run testsuite as non-root and root'''
        if self.kernel_version.endswith('-goldfish'):
            return self._skipped('An apparmor dependency (initramfs-tools) cannot be met on goldfish')

        build_dir = testlib.prepare_source('click-apparmor', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)
        os.chdir(build_dir)

        # First as non-root
        for user in [self.builder.login, 'root']:
            (rc, report) = testlib.cmd(['sudo', '-u', user,
                                        './test-clicktool.py'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertFalse('FAIL' in report, "Found 'FAIL' in:\n%s" % (report))

    def test_zz_autopkgtests(self):
        '''Run autopkgtests'''
        if self.kernel_version.endswith('-goldfish'):
            return self._skipped('An apparmor dependency (initramfs-tools) cannot be met on goldfish')

        build_dir = testlib.prepare_source('click-apparmor', \
                                      self.builder, \
                                      self.cached_src, \
                                      os.path.join(self.tmpdir, \
                                        os.path.basename(self.cached_src)), \
                                      self.patch_system)

        os.chdir(build_dir)
        # Now run the autopackage tests
        tests = glob.glob("./debian/tests/*")
        for f in tests:
            if os.path.isdir(f):
                continue
            elif os.path.basename(f) == "control":
                continue
            elif os.path.basename(f) == "run_testsuite-as-root":
                # we already did this above
                continue
            print(" %s" % os.path.basename(f))

            adttmp = os.path.join(self.tmpdir, os.path.basename(f))
            os.mkdir(adttmp)
            os.environ['ADTTMP'] = adttmp

            os.chmod(f, 0755)
            (rc, report) = testlib.cmd(f)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertFalse('\nFAIL' in report, "Found '\\nFAIL' in:\n%s" % (report))


if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ClickAppArmorTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ClickAppArmorTestsuite))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
