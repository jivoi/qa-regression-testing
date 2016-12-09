#!/usr/bin/python
#
#    test-pptpd.py quality assurance test script
#    Copyright (C) 2008 Canonical Ltd.
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
    How to run against a clean schroot named 'feisty':
        schroot -c feisty -u root -- sh -c 'apt-get -y install pptpd pptp-linux && ./test-pptpd.py -v'

    TODO:
    - broken on Natty. Seems the script needs to be generalized. Review
      http://poptop.sourceforge.net/dox/debian-howto.phtml
'''

# QRT-Packages: pptpd pptp-linux
# QRT-Privilege: root

import unittest, subprocess, time, signal
import testlib

class PPTPTest(testlib.TestlibCase):
    '''Test pptp daemon tunnels.'''

    def onetime_setUp(self):
        '''Set up prior to test_* functions'''
        testlib.config_replace('/etc/pptpd.conf','''#
option /etc/ppp/options.pptpd
logwtmp
''')

        testlib.config_replace('/etc/ppp/options.pptpd','''#
name pptpd
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
proxyarp
lock
nobsdcomp 
novj
novjccomp
nologfd
''')

        testlib.config_replace('/etc/ppp/peers/pptp-tunnel','''#
pty "pptp localhost --nolaunchpppd"
name tester
remotename pptpd
require-mppe-128
file /etc/ppp/options.pptp
ipparam pptp-tunnel
''')
        subprocess.call(['/etc/init.d/pptpd', 'stop'], stdout=subprocess.PIPE)
        self.assertTrue(subprocess.call(['/etc/init.d/pptpd', 'start'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0)

    def onetime_tearDown(self):
        '''Clean up after test_* functions'''
        testlib.config_restore('/etc/ppp/peers/pptp-tunnel')
        testlib.config_restore('/etc/ppp/options.pptpd')
        testlib.config_restore('/etc/pptpd.conf')

    def test_00_initialize(self):
        '''Set up initial tunnel'''
        self.onetime_setUp()

    def _connectivity_on(self,retry=False):
        self.pptp_proc = subprocess.Popen(['pon', 'pptp-tunnel', 'debug', 'dump', 'logfd', '2', 'nodetach'], stdout=subprocess.PIPE) #, stderr=subprocess.STDOUT)
        # Stall for tunnel to fail or come up
        for pause in range(8):
            if self.pptp_proc.poll() != None:
                # The command has aborted
                #print 'tunnel aborted'
                break
            #print 'tick...'
            time.sleep(1)

        # do ping test if tunnel still running
        rc = 1
        if self.pptp_proc.returncode == None:
            #print 'ping test'
            rc = subprocess.call(['ping', '-s', '192.168.0.1', '192.168.1.1', '-c1', '-w4'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        # attempt a retry
        if retry and rc != 0:
            # Initial connection always fails after server restart(?!)
            # so repeat test once at least.
            #print 'restart connectivity test'
            self.pptp_proc.wait()
            self._connectivity_on()
        else:
            self.assertTrue(rc == 0)

    def test_connectivity_on(self):
        '''Connected remote device pingable'''
        self._connectivity_on(retry=True)

    def test_disconnected(self):
        '''Disconnected remote device unpingable'''
        # hm, child process term is killing test runner
        signal.signal(signal.SIGTERM,signal.SIG_IGN)

        # shutdown tunnel
        subprocess.call(['poff', 'pptp-tunnel'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(1)
        signal.signal(signal.SIGTERM,signal.SIG_DFL)

        self.assertFalse(subprocess.call(['ping', '-s', '192.168.0.1', '192.168.1.1', '-c1', '-w4'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT) == 0)

    def test_zz_cleanup(self):
        '''Clean up configurations'''
        self.onetime_tearDown()

if __name__ == '__main__':
    unittest.main()
