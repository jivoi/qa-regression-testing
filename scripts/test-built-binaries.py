#!/usr/bin/python
#
#    test-built-binaries.py quality assurance test script for built-binaries
#    Copyright (C) 2009-2012 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#            Jamie Strandboge <jamie@canonical.com>
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
# QRT-Packages: aptitude binutils
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: hardening-includes
# files and directories required for the test to run:
# QRT-Depends: built-binaries

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install aptitude && ./test-built-binaries.py -v'
'''


import unittest, subprocess, sys, os, tempfile, glob, re
import testlib

try:
    from private.qrt.BuiltBinaries import PrivateBuiltBinariesTest
except ImportError:
    class PrivateBuiltBinariesTest(object):
        '''Empty class'''
    #print >>sys.stdout, "Skipping private tests"

class BuiltBinariesTest(testlib.TestlibCase, PrivateBuiltBinariesTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="built-binaries-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.fs_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def is_installed(self, binary):
        # always download!
        return False
        rc, report = testlib.cmd(['dpkg', '-l',binary])
        if rc != 0:
            return False
        found = False
        for line in [x.strip() for x in report.splitlines()]:
            if len(line)<1 or line[1] != 'i':
                continue
            state, pkg = line.split()[0:2]
            if pkg == binary:
                found = True
                break
        return found

    def unpack(self, binary):
        root = os.path.join(self.tempdir,binary)
        prev_dir = os.path.abspath('.')
        os.chdir(self.tempdir)
        rc, report = testlib.cmd(['aptitude','download',binary])
        self.assertEquals(rc, 0, report)
        downloaded = glob.glob('%s_*.deb' % (binary))
        self.assertEquals(len(downloaded),1,report)
        dest = os.path.join(self.tempdir, downloaded[0])
        os.chdir(prev_dir)
        self.assertShellExitEquals(0, ['dpkg-deb','-x',dest,root], stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, msg="Could not unpack '%s':" % (dest))
        self.assertTrue(os.path.exists(os.path.join(root,'usr')))
        return root

    def _is_elf(self, filename):
        # FIXME: .so files aren't stack protected??
        return not filename.endswith('.so') and not '.so.' in filename and os.path.isfile(filename) and open(filename).read(4) == '\x7fELF'

    def _get_package_elfs(self, binary):
        rc, report = testlib.cmd(['dpkg', '-L',binary])
        self.assertEquals(rc, 0, report)
        elfs = []
        for filename in [x.strip() for x in report.splitlines()]:
            if self._is_elf(filename):
                elfs.append(filename)
        return elfs

    def _get_path_elfs(self, dir):
        elfs = []
        def __add_if_elf(self, dir, fnames):
            for f in fnames:
                filename = os.path.join(dir,f)
                if self._is_elf(filename):
                    elfs.append(filename)
        os.path.walk(dir, __add_if_elf, self)
        return elfs

    # Some ELFs are so small that no function actually ends up
    # getting built with stack protectors.  These can be added
    # to the blacklist to be ignored.
    def _elfs_test(self, pkgs, blacklist=[], whitelist=[], want_pie=False, want_bindnow=False, want_stackprotector=True, want_relro=True, want_fortify=True, expected=None):

      if expected == None:
          expected = 0
          if self.lsb_release['Release'] < 8.10:
              self._skipped("only hardened in Intrepid and later")
              expected = 1

      for binary in pkgs:
        raw_elfs = []
        root = ''
        if self.is_installed(binary):
            raw_elfs = self._get_package_elfs(binary)
        else:
            root = self.unpack(binary)
            raw_elfs = self._get_path_elfs(root)

        hc_exe = '/usr/bin/hardening-check'
        if not os.path.exists(hc_exe):
            print >>sys.stderr, "WARN: could not find '%s'. Using 'built-binaries/hardening-check'" % (hc_exe)
            hc_exe = 'built-binaries/hardening-check'
        args = [hc_exe,'-q']
        if not want_pie:
            args += ['-p']
        if not want_bindnow:
            args += ['-b']
        if not want_stackprotector:
            args += ['-s']
        if not want_relro:
            args += ['-r']
        if not want_fortify:
            args += ['-f']
        # Remove ELFs in the blacklist
        elfs = [x for x in raw_elfs if len([pat for pat in blacklist if re.match(pat+'$', x[len(root):])])==0 ]
        # Keep only ELFs in the whitelist
        if len(whitelist):
            elfs = [x for x in elfs if len([pat for pat in whitelist if re.match(pat+'$', x[len(root):])])>0 ]
        self.assertTrue(len(elfs)>0, "No ELF binaries found in '%s'" % (binary))
        self.assertShellExitEquals(expected, args + elfs, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, msg="Hardening check failed on ELF binaries in '%s':" % (binary))

    def _elfs_test_pie(self, pkgs, release, want_fortify=True, want_stackprotector=True, want_relro=True, whitelist=[], blacklist=[]):
        pie = True
        if self.lsb_release['Release'] < release:
            # Only mention the PIEness after Intrepid
            if self.lsb_release['Release'] >= 8.10:
                self.announce("not expected to be PIE: %s" % ",".join(pkgs))
            pie = False
        bindnow = pie
        if bindnow:
            if self.lsb_release['Release'] < 10.04:
                self.announce("only BIND_NOW in Lucid and later")
                bindnow = False
        return self._elfs_test(pkgs, blacklist=blacklist, whitelist=whitelist, want_pie=pie, want_bindnow=bindnow, want_fortify=want_fortify, want_stackprotector=want_stackprotector, want_relro=want_relro)

    # Look at commonly installed stuff just to check for stack protector, fortify, etc.
    def test_bash(self):
        '''Testing bash'''
        stack=True
        fortify=True
        relro=True
        if self.lsb_release['Release'] == 8.10:
            self.announce("not hardened in Intrepid")
            stack = False
            fortify = False
            relro = False
        self._elfs_test(['bash'], want_relro=relro, want_stackprotector=stack, want_fortify=fortify, blacklist=['/usr/bin/clear_console'])

    def test_coreutils(self):
        '''Testing coreutils'''

        stackprotector = True
        if self.lsb_release['Release'] >= 10.10:
            # Prior to the 8.x coreutils, the internal rpl_vfprintf was causing
            # the need for stackprotector on almost every utility. This stopped,
            # meaning we need to skip half of the utils for stack protector, and
            # as a result, we scan twice.
            stackprotector = False
            blacklist = [
                '/bin/chmod',
                '/bin/echo',
                '/bin/false',
                '/bin/mknod',
                '/bin/pwd',
                '/bin/readlink',
                '/bin/rm',
                '/bin/sleep',
                '/bin/sync',
                '/bin/true',
                '/bin/uname',
                '/usr/bin/arch',
                '/usr/bin/basename',
                '/usr/bin/comm',
                '/usr/bin/dircolors',
                '/usr/bin/dirname',
                '/usr/bin/env',
                '/usr/bin/expand',
                '/usr/bin/fmt',
                '/usr/bin/fold',
                '/usr/bin/groups',
                '/usr/bin/hostid',
                '/usr/bin/id',
                '/usr/bin/join',
                '/usr/bin/link',
                '/usr/bin/logname',
                '/usr/bin/md5sum',
                '/usr/bin/md5sum.textutils',
                '/usr/bin/mkfifo',
                '/usr/bin/nice',
                '/usr/bin/nohup',
                '/usr/bin/nproc',
                '/usr/bin/paste',
                '/usr/bin/pathchk',
                '/usr/bin/printenv',
                '/usr/bin/runcon',
                '/usr/bin/sha1sum',
                '/usr/bin/sha224sum',
                '/usr/bin/sha256sum',
                '/usr/bin/sha384sum',
                '/usr/bin/sha512sum',
                '/usr/bin/tr',
                '/usr/bin/tsort',
                '/usr/bin/tty',
                '/usr/bin/unexpand',
                '/usr/bin/uniq',
                '/usr/bin/unlink',
                '/usr/bin/users',
                '/usr/bin/whoami',
                '/usr/bin/yes']
            self._elfs_test(['coreutils'], blacklist=blacklist)

        self._elfs_test(['coreutils'], want_stackprotector=stackprotector)

    # Examine expected PIE binaries
    def test_openssh(self):
        '''Testing openssh'''

        # The logic here is more complex due to the early PIE and late BINDNOW
        pie = True
        hardened = True
        bindnow = True
        if self.lsb_release['Release'] < 8.04:
            self._skipped("only PIE in Hardy and later")
            pie = False
            bindnow = False
            hardened = False
        else:
            if self.lsb_release['Release'] < 8.10:
                self._skipped("only hardened in Intrepid and later")
                hardened = False
                bindnow = False
            else:
                if self.lsb_release['Release'] < 10.04:
                    self.announce("only BIND_NOW in Lucid and later")
                    bindnow = False

        pkgs = ['openssh-client','openssh-server']
        self._elfs_test(pkgs, want_pie=pie, want_bindnow=bindnow, want_stackprotector=hardened, want_relro=hardened, want_fortify=hardened, expected=0)

    def test_apache2(self):
        '''Testing apache2'''
        pkg = 'apache2.2-bin'
        if self.lsb_release['Release'] < 9.10:
            pkg = 'apache2-mpm-prefork'
        self._elfs_test_pie([pkg],8.10,blacklist=['/usr/sbin/httxt2dbm'])

    def test_bind9(self):
        '''Testing bind9'''
        self._elfs_test_pie(['bind9'],8.10,blacklist=['/usr/sbin/named-journalprint','/usr/sbin/genrandom'])

    def test_openldap(self):
        '''Testing openldap'''
        self._elfs_test_pie(['slapd'],8.10)

    def test_postfix(self):
        '''Testing postfix'''
        stacked = ['/usr/sbin/smtp-sink','/usr/lib/postfix/fsstone','/usr/lib/postfix/smtp','/usr/lib/postfix/lmtp']
        self._elfs_test_pie(['postfix'],8.10,whitelist=stacked)

    def test_cups(self):
        '''Testing cups'''
        pkg = 'cups'
        if self.lsb_release['Release'] < 8.10:
            pkg = 'cupsys'
        tiny=['/usr/lib/cups/monitor/bcp','/usr/lib/cups/monitor/tbcp','/usr/lib/cups/backend-available/scsi','/usr/lib/cups/daemon/cups-exec','/usr/lib/cups/filter/gziptoany']
        self._elfs_test_pie([pkg],8.10,blacklist=tiny)

    def test_postgresql(self):
        '''Testing postgresql'''
        pkg = 'postgresql-9.1'
        if self.lsb_release['Release'] < 8.04:
            pkg = 'postgresql-8.1'
        elif self.lsb_release['Release'] < 9.10:
            pkg = 'postgresql-8.3'
        elif self.lsb_release['Release'] < 11.10:
            pkg = 'postgresql-8.4'
        self._elfs_test_pie([pkg],8.10)

    def test_samba(self):
        '''Testing samba'''
        self._elfs_test_pie(['samba'],8.10)

    def test_dovecot(self):
        '''Testing dovecot'''
        if self.lsb_release['Release'] < 11.10:
            self._elfs_test_pie(['dovecot-imapd','dovecot-pop3d'],8.10)
        else:
            # FIXME: we need some kind of bitmap of which bins are expected to
            # do what.
            nostack_nofortify = ['/usr/lib/dovecot/imap-login']
            nofortify = ['/usr/lib/dovecot/imap', '/usr/lib/dovecot/pop3', '/usr/lib/dovecot/pop3-login']
            imap = nofortify + nostack_nofortify
            self._elfs_test_pie(['dovecot-imapd','dovecot-pop3d'],8.10,whitelist=nofortify, want_fortify=False)
            self._elfs_test_pie(['dovecot-imapd'],8.10,whitelist=nostack_nofortify, want_fortify=False, want_stackprotector=False)

    def test_dhcp3(self):
        '''Testing dhcp3'''
        pkgs = []
        if self.lsb_release['Release'] < 11.04:
            pkgs += ['dhcp3-server', 'dhcp3-client']
        else:
            pkgs += ['isc-dhcp-server', 'isc-dhcp-client']
        self._elfs_test_pie(pkgs,8.10)

    def test_ntp(self):
        '''Testing ntp'''
        tiny=['/usr/sbin/ntptime','/usr/bin/tickadj']
        self._elfs_test_pie(['ntp'],9.10,blacklist=tiny)

    def test_amavisd(self):
        '''Testing amavisd-milter'''
        if self.lsb_release['Release'] < 8.10:
            self._skipped("broken in Hardy and earlier")
            return
        tiny=['/usr/sbin/amavis']
        pkg = 'amavisd-milter'
        if self.lsb_release['Release'] < 11.04:
            pkg = 'amavisd-new-milter'
        self._elfs_test_pie([pkg], 9.10, blacklist=tiny)

    def test_squid(self):
        '''Testing squid'''
        pkg = 'squid3'
        if self.lsb_release['Release'] < 12.04:
            pkg = 'squid'
        prefix = '/usr/lib/%s/' %(pkg)
        tiny=[prefix + 'unlinkd', prefix + 'logfile-daemon', prefix + 'yp_auth', prefix + 'getpwnam_auth', prefix + 'getpwname_auth']
        self._elfs_test_pie([pkg], 9.10, blacklist=tiny)

    def test_cyrussasl(self):
        '''Testing cyrus-sasl2'''
        tiny=['/usr/bin/sasl-sample-client','/usr/sbin/sasl-sample-server','/usr/sbin/saslpluginviewer']
        self._elfs_test_pie(['sasl2-bin'],9.10,blacklist=tiny)

    def test_exim4(self):
        '''Testing exim4'''
        self._elfs_test_pie(['exim4-daemon-light','exim4-daemon-heavy'],9.10)

    def test_nagios(self):
        '''Testing nagios'''
        pkg = 'nagios3-core'
        if self.lsb_release['Release'] < 10.04:
            pkg = 'nagios3'
        if self.lsb_release['Release'] < 8.10:
            pkg = 'nagios2'
        if self.lsb_release['Release'] < 8.04:
            pkg = 'nagios-text'
        self._elfs_test_pie([pkg],9.10)

    def test_nagiosplugins(self):
        '''Testing nagios-plugins'''
        tiny=['/usr/lib/nagios/plugins/check_(cluster|dummy|load)'] # from -basic
        self._elfs_test_pie(['nagios-plugins-basic','nagios-plugins-standard','nagios-plugins-extra'],9.10,blacklist=tiny)

    def test_xinetd(self):
        '''Testing xinetd'''
        self._elfs_test_pie(['xinetd'],9.10)

    def test_ipsec_tools(self):
        '''Testing ipsec-tools'''
        if self.lsb_release['Release'] > 11.04:
            self._elfs_test_pie(['racoon'],9.10,whitelist=['/usr/sbin/racoon'],want_fortify=False)
        else:
            self._elfs_test_pie(['ipsec-tools'],9.10)

    def test_mysql(self):
        '''Testing mysql'''
        pkg='mysql-server-5.5'
        if self.lsb_release['Release'] < 9.04:
            pkg = 'mysql-server-5.0'
        elif self.lsb_release['Release'] < 12.04:
            pkg = 'mysql-server-5.1'
        self._elfs_test_pie([pkg],9.10,blacklist=['/usr/bin/innochecksum'])

    def test_asterisk(self):
        '''Testing asterisk (universe)'''
        pkg='asterisk'
        if self.lsb_release['Release'] < 8.04:
            pkg='asterisk-classic'
        tiny=['/usr/sbin/astcanary']
        self._elfs_test_pie([pkg],9.10,blacklist=tiny)

    def test_sendmail(self):
        '''Testing sendmail (universe)'''
        fortify=True
        if self.lsb_release['Release'] == 8.10:
            self.announce("not fortified in Intrepid")
            fortify = False
        self._elfs_test_pie(['sendmail-bin'],9.10,want_fortify=fortify)

    def test_openbsd_inetd(self):
        '''Testing openbsd-inetd (universe)'''
        self._elfs_test_pie(['openbsd-inetd'],9.10)

    def test_wireshark(self):
        '''Testing wireshark (universe)'''
        pkg='wireshark'
        if self.lsb_release['Release'] < 8.04:
            pkg = 'ethereal'
        self._elfs_test_pie([pkg],9.10)

    def test_evince(self):
        '''Testing evince'''
        # Ignore helpers that are so tiny they miss various hardening elements
        self._elfs_test_pie(['evince'],10.04,whitelist=['/usr/bin/evince'])

    def test_firefox(self):
        '''Testing firefox'''
        pkg = 'firefox'
        if self.lsb_release['Release'] < 10.04:
            pkg = 'firefox-3.5'
            if self.lsb_release['Release'] < 9.10:
                pkg = 'firefox-3.0'
                if self.lsb_release['Release'] < 8.04:
                    pkg = 'firefox'
        self._elfs_test_pie([pkg],10.04,blacklist=['/usr/lib/.*/(plugin-container|ffox-[^/]*beta-profile-migration-dialog)'])

    def test_chromium(self):
        '''Testing chromium-browser'''
        if self.lsb_release['Release'] < 10.04:
            self._skipped("does not exist before Lucid")
            return
        self._elfs_test_pie(['chromium-browser'],10.04,blacklist=['/usr/lib/chromium-browser/nacl_irt_x86_64\.nexe'])

    def test_tiff(self):
        '''Testing tiff tools'''
        self._elfs_test_pie(['libtiff-tools'],11.04, want_stackprotector=False)

    def test_totem(self):
        '''Testing totem'''
        if self.lsb_release['Release'] < 11.10:
            self._elfs_test_pie(['totem'],11.04, whitelist=['/usr/bin/totem'], want_fortify=False)
            self._elfs_test_pie(['totem'],11.04, blacklist=['/usr/bin/totem'], want_stackprotector=False, want_fortify=False)
        else:
            self._elfs_test_pie(['totem'],11.04, want_stackprotector=False, want_fortify=False)

    def test_gnome_control_center(self):
        '''Testing gnome-control-center's font thumbnailer'''
        if self.lsb_release['Release'] > 11.04:
            self._skipped("does not exist after Natty")
            return
        self._elfs_test_pie(['gnome-control-center'],11.04,whitelist=['/usr/bin/gnome-thumbnail-font'], want_stackprotector=False, want_fortify=False)

    def test_qemu_kvm(self):
        '''Testing qemu-kvm'''
        self._elfs_test_pie(['qemu-kvm'],11.10, want_relro=False)

    def test_pidgin(self):
        '''Testing pidgin'''
        # skip libpurple0 because it doesn't contain any non-library binaries
        # skip libpurple-bin because only binaries are python and shell
        # scripts
        self._elfs_test_pie(['pidgin', 'finch'], 11.10)

    def test_openvswitch(self):
        '''Testing openvswitch'''
        pkgs = ['openvswitch-brcompat', 'openvswitch-common', 'openvswitch-controller', 'openvswitch-switch']
        self._elfs_test_pie(pkgs,12.10)

    def test_qpdf(self):
        '''Testing qpdf'''
        self._elfs_test_pie(['qpdf'],12.10, want_fortify=False)

if __name__ == '__main__':
    # simple
    unittest.main()
