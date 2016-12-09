#!/usr/bin/python
#
#    test-cups.py quality assurance test script
#    Copyright (C) 2008-2015 Canonical Ltd.
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

'''
  *** IMPORTANT ***
  DO NOT RUN ON A PRODUCTION SERVER.
  *** IMPORTANT ***

  How to run (lucid+):
    $ sudo apt-get -y install python-pexpect lsb-release cups cups-client elinks gnuplot imagemagick libtiff-tools
    $ sudo ./test-cups.py -v'

  NOTES:
    - assumes no printers are defined (HTTP test will fail if cups-pdf is
      installed. Can remove the printer with 'lpadmin -x PDF').

  BROWSE AND EXPORT TESTING
    - To test exporting, run on the server:
      $ ./test-cups.py server-start

    - To test browsing, run on the client:
      $ ./test-cups.py client

    - When done testing exporting:
      $ ./test-cups.py server-stop

  BROWSING OVERVIEW (12.10 and earlier only)
    - To test browsing, need a printer on the local LAN configured like so:
      $ sudo lpadmin -p test-cupsys -E -v file:///dev/null -P /usr/share/ppd/cups-included/HP/laserjet.ppd
      $ lpstat -p
      $ sudo /usr/share/cups/enable_browsing 1 (or cupsctl --remote-printers)
      $ sudo /usr/share/cups/enable_sharing 1 (or cupsctl --share-printers)

      It will take about 30 seconds for the printer to show up. To test the
      client without running this script, do:
      $ sudo /etc/init.d/cupsys stop
      $ sudo rm /var/cache/cups/remote.cache
      $ sudo /etc/init.d/cupsys start
      $ lpstat -t || sleep 45 && lpstat -t

  TODO:
    - SSL connections
    - BSD compatibility (lpr, lpc, etc)
'''

# QRT-Depends: cups data private/qrt/cups.py
# QRT-Packages: cups elinks libtiff-tools python-pexpect gnuplot imagemagick apparmor
# QRT-Alternates: cups-browsed:!lucid cups-browsed:!precise cups-browsed:!quantal
# QRT-Privilege: root

import unittest, subprocess
import os, shutil, socket, sys, tempfile, testlib, time, pexpect

try:
    from private.qrt.cups import PrivateCupsTest
except ImportError:
    class PrivateCupsTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class CupsysCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        self.initscript = "/etc/init.d/cups"
        self.url = "http://localhost:631/"
        self.pidfile = "/var/run/cups/cupsd.pid"
        self.browsed_conf = "/etc/cups/cups-browsed.conf"

        testlib.config_replace('/etc/cups/passwd.md5',
                               '''ubuntutest:lp:a20a0d70ab227981fce5bb7a204902e5
''')

        self._stop()
        self._start()

        if self.lsb_release['Release'] >= 13.10:
            testlib.config_replace(self.browsed_conf,
                                   '''BrowseRemoteProtocols dnssd cups
BrowseLocalProtocols none
''')
            self._stop_browsed()
            self._start_browsed()


        self.tempdir = ""
        self.printers = []

    def _tearDown(self):
        '''Clean up after each test_* function'''
        testlib.config_restore('/etc/cups/cupsd.conf')
        testlib.config_restore('/etc/cups/passwd.md5')

        if self.lsb_release['Release'] >= 13.10:
            testlib.config_restore(self.browsed_conf)
            self._stop_browsed()

        for p in self.printers:
            if p != "test_net":
                self._remove_printer(p)

        self._stop()
        time.sleep(2)
        testlib.cmd(['killall', 'cupsd'])

        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _start(self):
        '''Start CUPS'''
        if self.lsb_release['Release'] <= 13.04:
            rc, report = testlib.cmd([self.initscript, 'start'])
        elif self.lsb_release['Release'] <= 14.10:
            rc, report = testlib.cmd(['start', 'cups'])
        else:
            rc, report = testlib.cmd(['systemctl', 'start', 'cups'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(2)

        rc, report = testlib.cmd(['lpstat', '-r'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, "is running")

    def _start_browsed(self):
        '''Start CUPS browsed'''

        # Now have a separate daemon in saucy+ for browsing
        if self.lsb_release['Release'] <= 13.04:
            return

        if self.lsb_release['Release'] <= 14.10:
            rc, report = testlib.cmd(['start', 'cups-browsed'])
        else:
            rc, report = testlib.cmd(['systemctl', 'start', 'cups-browsed'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(2)

    def _stop(self):
        '''Stop CUPS'''
        expected = 0
        if self.lsb_release['Release'] <= 13.04:
            rc, report = testlib.cmd([self.initscript, 'stop'])
        elif self.lsb_release['Release'] <= 14.10:
            rc, report = testlib.cmd(['stop', 'cups'])
            if rc != expected and 'Unknown instance' in report:
                rc = 0
        else:
            rc, report = testlib.cmd(['systemctl', 'stop', 'cups'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _stop_browsed(self):
        '''Stop CUPS browsed'''

        if self.lsb_release['Release'] <= 13.04:
            return

        expected = 0
        if self.lsb_release['Release'] <= 14.10:
            rc, report = testlib.cmd(['stop', 'cups-browsed'])
        else:
            rc, report = testlib.cmd(['systemctl', 'stop', 'cups-browsed'])
        if rc != expected and 'Unknown instance' in report:
            rc = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _reload(self):
        '''Reload CUPS'''
        if self.lsb_release['Release'] <= 13.04:
            rc, report = testlib.cmd([self.initscript, 'force-reload'])
        elif self.lsb_release['Release'] <= 14.10:
            rc, report = testlib.cmd(['reload', 'cups'])
        else:
            rc, report = testlib.cmd(['systemctl', 'reload', 'cups'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _reload_browsed(self):
        '''Reload CUPS browsed'''

        if self.lsb_release['Release'] <= 13.04:
            return

        if self.lsb_release['Release'] <= 14.10:
            rc, report = testlib.cmd(['reload', 'cups-browsed'])
        else:
            rc, report = testlib.cmd(['systemctl', 'reload', 'cups-browsed'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _restart(self):
        '''Restart CUPS'''
        self._stop()
        self._start()

    def _restart_browsed(self):
        '''Restart CUPS browsed'''
        self._stop_browsed()
        self._start_browsed()

    def _enable_browsing(self, enable):
        '''Based on enable_browsing script'''
        self._stop()
        if os.path.exists('/var/cache/cups/remote.cache'):
            os.unlink('/var/cache/cups/remote.cache')
        self._start()

        # Cups in Saucy+ has cups-browsed
        if self.lsb_release['Release'] >= 13.10:
            if enable == "1":
                subprocess.call(['sed', '-i',
                                 "s/^BrowseRemoteProtocols.*$/BrowseRemoteProtocols dnssd cups/",
                                 self.browsed_conf])
                self._restart_browsed()
            else:
                subprocess.call(['sed', '-i',
                                 "s/^BrowseRemoteProtocols.*$/BrowseRemoteProtocols none/",
                                 self.browsed_conf])
                self._restart_browsed()
        else:
            if enable == "1":
                # old way
                #subprocess.call(['sed', '-ir', "s/^[[:space:]]*Listen[[:space:]]+localhost:631\\>/Listen 631/i", '/etc/cups/cupsd.conf'])
                subprocess.call(['cupsctl', '--remote-printers'])
                self._reload()
            else:
                # old way
                #subprocess.call(['sed', '-ir', "s/^[[:space:]]*(Port|Listen)[[:space:]]+631\\>/Listen 127.0.0.1:631/i", '/etc/cups/cupsd.conf'])
                subprocess.call(['cupsctl', '--no-remote-printers'])
                self._reload()

    def _enable_sharing(self, enable):
        '''Based on enable_browsing script'''
        self._stop()
        if os.path.exists('/var/cache/cups/remote.cache'):
            os.unlink('/var/cache/cups/remote.cache')
        self._start()

        # Cups in Saucy+ has cups-browsed
        if self.lsb_release['Release'] >= 13.10:
            if enable == "1":
                subprocess.call(['sed', '-i',
                                 "s/^BrowseLocalProtocols.*$/BrowseLocalProtocols dnssd cups/",
                                 self.browsed_conf])
                self._restart_browsed()
            else:
                subprocess.call(['sed', '-i',
                                 "s/^BrowseLocalProtocols.*$/BrowseLocalProtocols none/",
                                 self.browsed_conf])
                self._restart_browsed()

        # Also share with cups, even on Saucy+
        if enable == "1":
            subprocess.call(['cupsctl', '--share-printers'])
            self._reload()
        else:
            subprocess.call(['cupsctl', '--no-share-printers'])
            self._reload()

    def _add_printer(self, printer='test_printer', device='file:///dev/null', \
                     host=""):
        '''Add a printer'''

        if self.lsb_release['Release'] < 12.04:
            ppd_file = '/usr/share/ppd/cups-included/postscript.ppd'
        else:
            ppd_file = 'cups/postscript.ppd'

        if host == "":
            rc, report = testlib.cmd(['lpadmin', '-p', printer, '-E', '-v', \
                               device, '-P', ppd_file])
        else:
            rc, report = testlib.cmd(['lpadmin', '-h', host, '-p', printer, \
                               '-E', '-v', device])

        expected = 0
        if host != "":
            # CUPS adds the printer but gives a 'Bad device-uri' error
            expected = 1

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        report = self._list_printers(0, printer, host)
        self._word_find(report, printer)

        self.printers.append(printer)

    def _remove_printer(self, printer='test_printer'):
        '''Remove a printer'''
        rc, report = testlib.cmd(['lpadmin', '-x', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._list_printers(1)

        self.printers.remove(printer)

    def _disable_printer(self, printer='test_printer'):
        '''Disable a printer'''
        rc, report = testlib.cmd(['cupsdisable', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        report = self._list_printers()
        self._word_find(report, "disabled")

    def _enable_printer(self, printer='test_printer'):
        '''Enable a printer'''
        rc, report = testlib.cmd(['cupsenable', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        report = self._list_printers()
        self._word_find(report, "is idle")

    def _submit_job(self, printer='test_printer', host="", expected=0, \
                    testpage='cups/testprint.ps'):
        '''Submit a print job'''
        if host == "":
            rc, report = testlib.cmd(['lp', '-d', printer, testpage])
        else:
            rc, report = testlib.cmd(['lp', '-d', printer, '-h', host, \
                                      testpage])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _list_printers(self, expected=0, printer='test_printer', host=""):
        '''List printers with lpstat'''
        if host == "":
            rc, report = testlib.cmd(['lpstat', '-p', printer])
        else:
            rc, report = testlib.cmd(['lpstat', '-h', host, '-p', printer])

        # lpstat -p returns non-zero if no printers
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        return report

    def _word_find(self,report,content, invert=False):
        '''Check for a specific string'''
        if invert:
            warning = 'Found "%s" in: \n' % content
            self.assertTrue(content not in report, warning + report)
        else:
            warning = 'Could not find "%s" in: \n' % content
            self.assertTrue(content in report, warning + report)

    def _test_url(self, url="http://localhost:631/", content="", invert=False):
        '''Test the given url'''
        rc, report = testlib.cmd(['elinks', '-verbose', '2', '-no-home', '1', '-dump', url])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if content != "":
            self._word_find(report, content, invert)

    def _test_url_source(self, url="http://localhost:631/", content="", invert=False):
        '''Test the given url'''
        rc, report = testlib.cmd(['elinks', '-verbose', '2', '-no-home', '1', '-source', url])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if content != "":
            self._word_find(report, content, invert)

    def _test_raw(self, request="", content="", host="localhost", port=631, invert = False, limit=4096):
        '''Test the given url with a raw socket to include headers'''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(request)
        time.sleep(2)
        data = s.recv(limit)
        s.close()

        if content != "":
            self._word_find(data, content, invert)


class BasicTest(CupsysCommon, PrivateCupsTest):
    '''Test basic functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        CupsysCommon._setUp(self)

    def tearDown(self):
        '''Shutdown methods'''
        CupsysCommon._tearDown(self)

        if os.path.exists('/var/cache/cups/rss/shadow'):
            os.unlink('/var/cache/cups/rss/shadow')

    def _setup_cups_leaf(self,browse_port="632"):
        '''Setup a second cupsd server'''
        browse_dir = tempfile.mkdtemp(dir='/tmp')
        self.tempdir = browse_dir
        cupsd_file = os.path.join(browse_dir, "cupsd.conf")
        cupsfiles_file = os.path.join(browse_dir, "cups-files.conf")
        cupsd_contents = '''
Browsing On
Listen 127.0.0.1:''' + browse_port + '''
Listen ''' + browse_dir + '''/cups.sock
MaxLogSize 0
LogLevel debug2
PreserveJobHistory Yes
<Policy default>
<Limit All>
Order Deny,Allow
Deny from all
Allow from 127.0.0.1
</Limit>
</Policy>
'''

        cupsfiles_contents = '''
FileDevice yes
Printcap
ServerRoot ''' + browse_dir + '''
ServerBin ''' + browse_dir + '''/bin
StateDir ''' + browse_dir + '''
CacheDir ''' + browse_dir + '''/cache
RequestRoot ''' + browse_dir + '''/spool
TempDir ''' + browse_dir + '''/spool/temp
PidFile ''' + browse_dir + '''/cupsd.pid
AccessLog ''' + browse_dir + '''/log/access_log
ErrorLog ''' + browse_dir + '''/log/error_log
PageLog ''' + browse_dir + '''/log/page_log
'''

        # See if cups has been updated for CVE-2012-5519. If so, this new
        # config file should exist, in which case, we need to create it
        # for the second cupsd server also.
        if os.path.exists("/etc/cups/cups-files.conf"):
            # Create cups-files.conf
            try:
                fh = open(cupsfiles_file, 'w')
                fh.write(cupsfiles_contents)
                fh.close()
            except:
                raise
        else:
            # Append the config items to the main file
            cupsd_contents += cupsfiles_contents

        # Create cupsd.conf
        try:
            fh = open(cupsd_file, 'w')
            fh.write(cupsd_contents)
            fh.close()
        except:
            raise


        os.makedirs(os.path.join(browse_dir, "spool/temp"))
        os.makedirs(os.path.join(browse_dir, "cache"))
        os.makedirs(os.path.join(browse_dir, "log"))
        os.makedirs(os.path.join(browse_dir, "bin"))

        subprocess.call(['touch', os.path.join(browse_dir, 'printers.conf')])
        subprocess.call(['cp', '/usr/sbin/cupsd', os.path.join(browse_dir, \
                                                               'bin')])
        if (os.path.exists('/etc/cups/mime.convs')):
            subprocess.call(['cp', '/etc/cups/mime.convs', browse_dir])
        if (os.path.exists('/etc/cups/mime.types')):
            subprocess.call(['cp', '/etc/cups/mime.types', browse_dir])

        return [ browse_dir, os.path.join(browse_dir, 'bin/cupsd'), \
                 cupsd_file ]

    def _get_my_ip(self):
        '''Attempt to get local ip address'''
        # Yes, this is awful.
        rc, report = testlib.cmd(["/sbin/ifconfig"])
        return report.split("\n")[1].split()[1][5:]

    def test_lpinfo(self):
        '''Test lpinfo'''
        rc, report = testlib.cmd(['lpinfo', '-m'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['lpinfo', '-v'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # The following used to have "direct parallel" also, but some computers
        # used for testing don't have parallel ports anymore...
        devices = ['socket', 'http', 'ipp', 'lpd']
        for x in devices:
            self._word_find(report, x)

    def test_lpstat(self):
        '''Test lpstat'''
        self._list_printers(1)

    def test_add_remove_printer(self):
        '''Test add/remove printer'''
        printer = "test_printer"

        self._add_printer(printer)
        rc, report = testlib.cmd(['lpstat', '-t'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, printer)

        self._remove_printer(printer)

    def test_enable_disable(self):
        '''Test enable/disable of printer'''
        self._add_printer()
        self._disable_printer()
        self._enable_printer()
        self._remove_printer()

    def test_lpoptions(self):
        '''Test lpoptions'''
        printer = 'test_printer'
        self._add_printer(printer)

        rc, report = testlib.cmd(['lpoptions', '-d', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, printer)

        self._remove_printer()

    def test_lppasswd(self):
        '''Test lppasswd'''

        # Vivid no longer ships with lppasswd or support for digest auth
        if self.lsb_release['Release'] >= 15.04:
            return self._skipped("Skipped: lppasswd no longer supported")

        expected = 0

        # Let's try changing a password
        child = pexpect.spawn('lppasswd ubuntutest')
        time.sleep(0.2)
        child.expect('.* password:', timeout=5)
        time.sleep(0.2)
        child.sendline('password123')
        time.sleep(0.2)
        child.expect('.* password again:', timeout=5)
        time.sleep(0.2)
        child.sendline('password123')
        time.sleep(0.2)
        child.close()

        self.assertEquals(child.exitstatus, expected, "lppasswd returned %d" %(child.exitstatus))

        rc, report = testlib.cmd(['cat', '/etc/cups/passwd.md5'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._word_find(report, "ubuntutest:lp:a20a0d70ab227981fce5bb7a204902e5")

        # Let's try adding a new account
        child = pexpect.spawn('lppasswd -a anotheruser')
        time.sleep(0.2)
        child.expect('.* password:', timeout=5)
        time.sleep(0.2)
        child.sendline('yayaya123')
        time.sleep(0.2)
        child.expect('.* password again:', timeout=5)
        time.sleep(0.2)
        child.sendline('yayaya123')
        time.sleep(0.2)
        child.close()

        self.assertEquals(child.exitstatus, expected, "lppasswd returned %d" %(child.exitstatus))

        rc, report = testlib.cmd(['cat', '/etc/cups/passwd.md5'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._word_find(report, "anotheruser:lp:5e94a62fa7bb800c367d5ce90b455163")

    def test_queue(self):
        '''Test queue management'''
        printer = 'test_printer'
        self._add_printer(printer)
        self._disable_printer(printer)
        self._submit_job(printer)

        rc, report = testlib.cmd(['lpstat', '-o', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, printer)

        rc, report = testlib.cmd(['cancel', '-a', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._remove_printer(printer)

    def test_printing(self):
        '''Test printing'''
        self._add_printer()
        self._submit_job()
        self._remove_printer()

    def test_accept_reject(self):
        '''Test accept/reject'''
        printer = 'test_printer'
        self._add_printer(printer)

        rc, report = testlib.cmd(['reject', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._submit_job(printer, "", 1)

        rc, report = testlib.cmd(['accept', printer])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._submit_job(printer, "")

        self._remove_printer(printer)

    def test_http(self):
        '''Test HTTP'''
        self._enable_browsing('0')

        # web server takes a while to come up
        time.sleep(2)

        self._test_url(self.url + 'printers/', "No printers")

        printer = 'test_printer'
        self._add_printer(printer)

        self._test_url(self.url + 'printers/', printer)

        self._remove_printer(printer)

    def test_cve_2014_3537(self):
        '''Test CVE-2014-3537'''

        # web server takes a while to come up
        time.sleep(2)

        os.symlink('/etc/shadow', '/var/cache/cups/rss/shadow')

        self._test_url(self.url + 'rss/shadow', "root", invert=True)


    def test_ipp(self):
        '''Test ipp networking'''
        # Setup a shared printer
        printer = 'test_printer'

        # Setup a second cupsd
        browse_port = "632"
        (browse_dir, browse_bin, browse_conf) = self._setup_cups_leaf( \
                                                  browse_port)

        # Start the second cups
        rc, report = testlib.cmd([browse_bin, '-c', browse_conf])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        time.sleep(2)

        # Add printer to main cupsd
        self._add_printer(printer)

        # Add network printer
        net_printer = "test_net"
        self._add_printer(net_printer, \
                          "ipp://localhost:631/printers/test_printer", \
                          "localhost:632")
        rc, report = testlib.cmd(['lpstat', '-h', 'localhost:' + browse_port, \
                                  '-p'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, net_printer)

        self._submit_job(net_printer, "localhost:632")

    def test_apparmor(self):
        '''Test apparmor'''
        rc, report = testlib.check_apparmor('/usr/sbin/cupsd', 7.10, is_running=True)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.check_apparmor('/usr/lib/cups/backend/cups-pdf', 7.10, is_running=False)
        if rc < 0:
            return self._skipped(report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_lp690040(self):
        '''Test Upstart/AppArmor integration (LP: #690040)'''
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("Skipped: CUPS upstart job only in 10.10 and higher")

        # vivid uses systemd and no longer loads the cups profile in the
        # service file/init script
        if self.lsb_release['Release'] >= 15.04:
            return self._skipped("Skipped: uses systemd")

        # Reproduce the race by doing:
        # 1. stop cups
        # 2. unload the profile
        # 3. start cups
        # 4. load the profile
        # 5. see if cups is confined

        self._stop()

        profile = '/etc/apparmor.d/usr.sbin.cupsd'
        testlib.cmd(["/sbin/apparmor_parser", '-R', profile])

        self._start()
        time.sleep(2)

        fd = open(self.pidfile, 'r')
        pid = fd.readline().rstrip('\n')
        fd.close()

        exe = "/usr/sbin/cupsd"
        self.assertTrue(testlib.check_pid(exe, pid))

        rc, report = testlib.cmd(["/sbin/apparmor_parser", '-r', '-W', profile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        fd = open("/proc/%s/attr/current" % (pid), 'r')
        attr_current = fd.readline().rstrip('\n')
        fd.close()
        result = "pid '%s' not in enforce mode:\n" % (pid)
        self.assertTrue("enforce" in attr_current, result + attr_current)

    def test_cve_2012_5519(self):
        '''Test CVE-2012-5519'''

        testlib.config_replace('/etc/cups/cupsd.conf', "", append=True)
        # Configure PageLog to point to a file lpadmin shouldn't be able to
        # read
        rc, report = testlib.cmd(["/usr/sbin/cupsctl", 'PageLog=/etc/shadow'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        time.sleep(2)
        self._test_url(self.url + 'admin/log/page_log', 'root:', invert=True)

    def test_cve_2014_2856(self):
        '''Test CVE-2014-2856'''

        testlib.config_replace('/etc/cups/cupsd.conf', "", append=True)

        subprocess.call(['sed', '-i', '-r', "s/^[[:space:]]*Listen[[:space:]]+localhost:631\\>/Port 631/i", '/etc/cups/cupsd.conf'])

        subprocess.call(['sed', '-i', '-r', "s/^[[:space:]]*Order[[:space:]]+allow,deny\\>/Encryption Required/ig", '/etc/cups/cupsd.conf'])

        self._stop()
        self._start()
        time.sleep(2)

        # This test doesn't work on the loopback interface, so we need
        # the real ip.
        ip = self._get_my_ip()
        url = "http://%s:631/<SCRIPT>alert('document.domain='+document.domain)</SCRIPT>.shtml" % ip

        self._test_url(url, '<SCRIPT>alert', invert=True)
        self._test_url(url, 'Forbidden')


class ClientTest(CupsysCommon):
    '''Test client functionality'''
    def setUp(self):
        '''Setup mechanisms'''
        CupsysCommon._setUp(self)
        self.failnote = '''
Browsing failed. For browse testing to work, there needs to be a printer on the
LAN that has both browsing and printer sharing enabled. One way to do this is
to run this script on the remote host with:

$ sudo ./test-cupsys.py server-start

When test are complete, run:

$ sudo ./test-cupsys.py server-stop

Please see the top of this test script for more details
'''

    def tearDown(self):
        '''Shutdown methods'''
        CupsysCommon._tearDown(self)

    def test_browse(self):
        '''Test client browsing'''
        printer = 'test-printer-server'

        # Test if no printers
        self._enable_browsing('0')

        rc, report = testlib.cmd(['lpstat', '-t'])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Test for added printer
        self._enable_browsing('1')

        rc, report = testlib.cmd(['lpstat', '-t'])
        expected = 0

        # Wait for browsing update
        if rc != expected:
            time.sleep(45)
            rc, report = testlib.cmd(['lpstat', '-t'])

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report + self.failnote)
        self._word_find(report, printer)

        self._enable_browsing('0')

    def test_printing(self):
        '''Test client printing'''
        printer = 'test-printer-server'

        # Test for added printer
        self._enable_browsing('1')

        rc, report = testlib.cmd(['lpstat', '-t'])
        expected = 0

        # Wait for browsing update
        if rc != expected:
            time.sleep(45)
            rc, report = testlib.cmd(['lpstat', '-t'])

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report + self.failnote)
        self._word_find(report, printer)

        self._submit_job(printer)
        self._enable_browsing('0')


class ServerStart(CupsysCommon):
    '''Start a server to be used with ClientTest'''
    def setUp(self):
        '''Setup mechanisms'''
        CupsysCommon._setUp(self)

    def tearDown(self):
        '''Shutdown methods'''
        pass

    def test_start(self):
        '''Start server exporting'''
        self._enable_browsing('1')
        self._enable_sharing('1')
        time.sleep(2)
        self._add_printer("test-printer-server")


class ServerStop(CupsysCommon):
    '''Stop a server to be used with ClientTest'''
    def setUp(self):
        '''Setup mechanisms'''
        self.initscript = "/etc/init.d/cups"
        self.url = "http://localhost:631/"
        self.browsed_conf = "/etc/cups/cups-browsed.conf"
        self.printers = []
        self.printers.append('test-printer-server')

    def tearDown(self):
        '''Shutdown methods'''
        printer = self.printers[0]
        rc, report = testlib.cmd(['lpstat', '-p', printer])
        if rc == 0:
            self._remove_printer(printer)

        self._enable_browsing('0')
        self._enable_sharing('0')

        self._stop()

    def test_stop(self):
        '''Stop server'''
        pass


class CupsysFilters(testlib.TestlibCase):
    '''Test various CUPS filters'''
    def setUp(self):
        '''Setup mechanisms'''
        self.tmpdir = tempfile.mkdtemp(dir='/tmp')

        self.input = os.path.join(self.tmpdir, "filter.in")
        self.output = os.path.join(self.tmpdir, "output.ps")
        self.filter_path = "/usr/lib/cups/filter"

    def tearDown(self):
        '''Shutdown methods'''
        testlib.recursive_rm(self.tmpdir)

    def _filter_test(self, filter, input=None, output=None, stderr=subprocess.PIPE, expected=0):
        '''Test the filter'''
        if not input:
            input = self.input

        if not os.path.exists(input):
            raise IOError, 'Could not open "%s" (not found)' % input

        if not output:
            output = self.output

        try:
            fh = open(output, 'w')
        except:
            raise

        subprocess.Popen([filter, '1', str(os.getuid()), "title_" + filter, \
                          "1", "-", input], stdout=fh.fileno(), \
                          stderr=stderr)
        fh.flush()
        fh.close()
        time.sleep(3)

        rc, report = testlib.cmd(['file', output])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if expected == 0:
            search_str = "PostScript"
            self.assertTrue(search_str in report, "Could not find '%s' in %s" % (search_str, report))

        os.unlink(output)

    def test_hpgl(self):
        '''Test filter: HP-GL and HP-GL/2'''
        # 'hpgl' is 'HP-GL' and 'pcl5' is 'HP-GL/2'
        for type in ['hpgl', 'pcl5']:
            self.hpoutput = os.path.join(self.tmpdir, type + ".out")

            text = '''set terminal %s
#set terminal png transparent nocrop enhanced font arial 8 size 420,320 
set output '%s'
set size .15,.15

set key left top Right noreverse enhanced autotitles box linetype -1 linewidth 1.000
set samples 400, 400
plot [-10:10] real(sin(x)**besj0(x))
''' % (type, self.hpoutput)

            try:
                fh = open(self.input, 'w')
                fh.write(text)
                fh.close()
            except:
                raise

            rc, report = testlib.cmd(['gnuplot', self.input])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            if type == "hpgl":
                command = ['cat', self.hpoutput]
                search = "PU;PA255,120;"
                if self.lsb_release['Release'] >= 10.10:
                    search = "PU;PA225,120;"
                if self.lsb_release['Release'] >= 11.04:
                    search = "PU;PA195,120;"
            else:
                search = "HP"
                command = ['file', self.hpoutput]

            rc, report = testlib.cmd(command)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)
            self.assertTrue(search in report, "Could not find '" + search + \
                            "' in " + report)

            if self.lsb_release['Release'] >= 11.10:
                if not os.path.exists(os.path.join(self.filter_path, "hpgltops")):
                    return self._skipped("Skipping hpgltops on 11.10+")

            self._filter_test(os.path.join(self.filter_path, "hpgltops"), self.hpoutput)

    def test_hpgl_badpens(self):
        '''Test filter: HP-GL (invalid pens)'''
        self.hpoutput = os.path.join(self.tmpdir, "hpglbad.out")

        text = '''set terminal hpgl
set output '%s'
set size .15,.15

set key left top Right noreverse enhanced autotitles box linetype -1 linewidth 1.000
set samples 400, 400
plot [-10:10] real(sin(x)**besj0(x))
''' % (self.hpoutput)

        try:
            fh = open(self.input, 'w')
            fh.write(text)
            fh.flush()
            fh.close()
        except:
            raise

        rc, report = testlib.cmd(['gnuplot', self.input])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        time.sleep(3)

        # Syntax comes from the PCL 5 Color Technical Reference Manual:
        # http://h20000.www2.hp.com/bc/docs/support/SupportManual/bpl13212/bpl13212.pdf
        subprocess.call(['sed', '-i', '0,/^SP1;/s//NP 1025;\\nSP1 1;/', self.hpoutput])

        if self.lsb_release['Release'] >= 11.10:
            if not os.path.exists(os.path.join(self.filter_path, "hpgltops")):
                return self._skipped("Skipping hpgltops on 11.10+")
        self._filter_test(os.path.join(self.filter_path, "hpgltops"), self.hpoutput)
        rc, report = testlib.cmd([os.path.join(self.filter_path, "hpgltops"), \
                          '1', str(os.getuid()), "title_hpgl", \
                          "1", "-", self.hpoutput], subprocess.STDOUT)
        search = "'NP' command with invalid number of pens"
        self.assertTrue(search in report, "Could not find '" + search + "'" + report)

        search = "'SP' command with invalid number of parameters"
        self.assertTrue(search in report, "Could not find '" + search + "'" + report)

    def test_texttops(self):
        '''Test filter: texttops'''
        text = '''some random
text
'''
        try:
            fh = open(self.input, 'w')
            fh.write(text)
            fh.close()
        except:
            raise

        self._filter_test(os.path.join(self.filter_path, "texttops"))

    def test_sgilib(self):
        '''Test filter: image-sgilib'''
        self.png = os.path.join(self.tmpdir, "out.png")
        self.sgi = os.path.join(self.tmpdir, "out.sgi")
        text = '''set terminal png transparent nocrop enhanced font arial 8 size 420,320 
set output '%s'
set size .15,.15

set key left top Right noreverse enhanced autotitles box linetype -1 linewidth 1.000
set samples 400, 400
plot [-10:10] real(sin(x)**besj0(x))
''' % (self.png)

        try:
            fh = open(self.input, 'w')
            fh.write(text)
            fh.close()
        except:
            raise

        # create a png
        rc, report = testlib.cmd(['gnuplot', self.input])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # convert to sgi
        rc, report = testlib.cmd(['convert', self.png, self.sgi])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test the sgi image
        self._filter_test(os.path.join(self.filter_path, "imagetops"), self.sgi)

    def test_png(self):
        '''Test filter: image-png'''
        # test the image
        self._filter_test(os.path.join(self.filter_path, "imagetops"), './data/well-formed.png')

    def test_tiff(self):
        '''Test filter: image-tiff'''
        # test the image
        self._filter_test(os.path.join(self.filter_path, "imagetops"), './data/well-formed.tiff')

    def test_CVE_2009_0163(self):
        '''Test filter: image-tiff (CVE-2009-0163)'''
        bytes = 268449774
        if not testlib.cwd_has_enough_space(os.getcwd(), bytes):
            return self._skipped("Skipped: not enough space (need %dK)" % (bytes / 1024))

        fn = os.path.join(self.tmpdir, 'large.tiff')
        shutil.copy('./data/well-formed.tiff', fn)

        # reset the ImageLength: tiffset -s 257 1073741840 ./large.tiff
        rc, report = testlib.cmd(['tiffset', '-s', '257', '1073741840', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # adjust the StripByteCounts: tiffset -s 279 16777217 ./large.tiff
        rc, report = testlib.cmd(['tiffset', '-s', '279', '16777217', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # adjust the StripOffsets: tiffset -s 273 16777217 ./large.tiff
        rc, report = testlib.cmd(['tiffset', '-s', '273', '16777217', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test the image
        assertshell = testlib.TimeoutFunction(self.assertShellExitEquals, 20)
        cmd = ['/usr/lib/cups/filter/imagetops', '1', '1000', 'foo', '1', '-', fn]

        if self.lsb_release['Release'] >= 12.04:
            expected_rc = 0
        else:
            expected_rc = 1

        try:
            assertshell(expected_rc, cmd)
        except:
            testlib.cmd(['killall', '-9', 'imagetops'])
            self.assertEquals(0, 1, "imagetops vulnerable")

if __name__ == '__main__':
    suite = unittest.TestSuite()
    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(BasicTest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(CupsysFilters))
    elif (sys.argv[1] == "client"):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ClientTest))
    elif (sys.argv[1] == "server-start"):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerStart))
    elif (sys.argv[1] == "server-stop"):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(ServerStop))
    else:
        print '''Usage:
  test-cups.py [-v]             basic tests
  test-cups.py server-start     start a server (to be used with 'client')
  test-cups.py server-stop      stop the server
  test-cups.py client           clients tests server-start'ed server
'''
        sys.exit(1)
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)

