#!/usr/bin/python
#
#    test-strongswan.py quality assurance test script for strongswan
#    Copyright (C) 2008-2015 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Based on test-ipsec-tools.py
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
# QRT-Packages: strongswan

'''
    This script must be run in two virtual machines. Install required
    packages with:
        sudo apt-get -y install strongswan

    This test is designed to be used with a partner system running the same
    script, and requires two unused private networks for the IPsec tunnel.
    The private networks don't need to be preconfigured in the virtual
    machines. Valid test types are:

    - 'ike1psk' to test pre-shared key authentication with IKEv1
    - 'ike2psk' to test pre-shared key authentication with IKEv2
    - 'ike1cert' to test x509 authentication with IKEv1
    - 'ike2cert' to test x509 authentication with IKEv2

    ./test-strongswan.py ike1psk|ike1cert|ike2psk|ike2cert SELF_IP SELF_NET REMOTE_IP REMOTE_NET [OPTIONS]

    Assuming the two machines will be "10.0.0.10" (with 192.168.10.0/24) and
    "10.0.0.22" (with 192.168.22.0/24), the way to run the tests with
    pre-shared keys would be:

    On system 10.0.0.10:
    sudo ./test-strongswan.py psk 10.0.0.10 192.168.10.0/24 10.0.0.22 192.168.22.0/24 -v

    On system 10.0.0.22:
    sudo ./test-strongswan.py psk 10.0.0.22 192.168.22.0/24 10.0.0.10 192.168.10.0/24 -v
'''

import unittest, sys, time, os
import testlib

iface = None
daemons_okay = False

class StrongswanTest(testlib.TestlibCase):
    '''Test that strongswan can set up an establish connections.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.ip_local  = ip_local
        self.ip_remote = ip_remote
        self.test_type = test_type
        self.net_local,  self.netmask_local  = net_local.split('/')
        self.net_remote, self.netmask_remote = net_remote.split('/')
        self.net_ip_local  = '.'.join(self.net_local.split('.')[:3] + ['1'])
        self.net_ip_remote = '.'.join(self.net_remote.split('.')[:3] + ['1'])

        global iface
        self.iface = iface

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_00_configure(self):
        '''Configure strongswan, interfaces, and routing'''

        # Stop daemon
        if self.lsb_release['Release'] >= 15.04:
            testlib.cmd(['sytemctl', 'stop','strongswan'])
        else:
            testlib.cmd(['stop','strongswan'])

        # Find interface
        global iface
        rc, output = testlib.cmd(['ip','-4','-o','addr','show'])
        self.assertEqual(rc, 0, output)
        for line in output.splitlines():
            iface_try = line.split(' ')[1]
            addr = line.split('inet ')[1].split('/')[0]
            if addr == self.ip_local:
                iface = self.iface = iface_try
                break
        self.assertNotEqual(self.iface, None, 'Cannot find interface for ip "%s":\n%s' % (self.ip_local,output))

        # Set up new network interface
        rc, output = testlib.cmd(['ifconfig','%s:test' % (self.iface),'%s/%s' % (self.net_ip_local, self.netmask_local)])
        # I have no idea why this is happening.  Is it maybe kvm?
        if 'Cannot assign requested address' in output:
            time.sleep(2)
            rc, output = testlib.cmd(['ifconfig','%s:test' % (self.iface),'%s/%s' % (self.net_ip_local, self.netmask_local)])
        self.assertEqual(rc, 0, 'ifconfig failed:\n%s' % (output))

        # Set up route to remote network
        rc, output = testlib.cmd(['ip','route','del','%s/%s' % (self.net_remote, self.netmask_remote)]) # remove old
        self.assertTrue(rc == 0 or rc == 2, 'Old route would not shutdown:\n%s' % (output))
        self.assertShellExitEquals(0,['ip','route','add','%s/%s' % (self.net_remote, self.netmask_remote),'dev',self.iface,'src',self.net_ip_local])

        if test_type == 'ike1psk':
            testlib.config_replace('/etc/ipsec.conf','''# Test config
config setup

conn %%default
	ikelifetime=60m
	keylife=20m
	rekeymargin=3m
	keyingtries=1
	keyexchange=ikev1
	authby=secret
	
conn net-net
	left=%s
	leftsubnet=%s/%s
	leftid=@leftgw
	leftfirewall=yes
	right=%s
	rightsubnet=%s/%s
	rightid=@rightgw
	auto=add

''' % (self.ip_local,
       self.net_local, self.netmask_local,
       self.ip_remote,
       self.net_remote, self.netmask_remote))

            testlib.config_replace('/etc/ipsec.secrets','''# Test config
@leftgw @rightgw : PSK 0sv+NkxY9LLdvwj4eCC2o/gGrdDF2d21jL
''')

        elif test_type == 'ike2psk':
            testlib.config_replace('/etc/ipsec.conf','''# Test config
config setup

conn %%default
	ikelifetime=60m
	keylife=20m
	rekeymargin=3m
	keyingtries=1
	keyexchange=ikev2
	authby=secret
	mobike=no
	
conn net-net
	left=%s
	leftsubnet=%s/%s
	leftid=@leftgw
	leftfirewall=yes
	right=%s
	rightsubnet=%s/%s
	rightid=@rightgw
	auto=add

''' % (self.ip_local,
       self.net_local, self.netmask_local,
       self.ip_remote,
       self.net_remote, self.netmask_remote))

            testlib.config_replace('/etc/ipsec.secrets','''# Test config
@leftgw @rightgw : PSK 0sv+NkxY9LLdvwj4eCC2o/gGrdDF2d21jL
''')

        elif test_type == 'ike1cert':
            testlib.config_replace('/etc/ipsec.conf','''# Test config
config setup

conn %%default
	ikelifetime=60m
	keylife=20m
	rekeymargin=3m
	keyingtries=1
	keyexchange=ikev1
	
conn net-net
	left=%s
	leftcert=hostacert.pem
	leftsubnet=%s/%s
	leftid=@leftgw
	leftfirewall=yes
	right=%s
	rightsubnet=%s/%s
	rightid=@rightgw
	auto=add

''' % (self.ip_local,
       self.net_local, self.netmask_local,
       self.ip_remote,
       self.net_remote, self.netmask_remote))

            testlib.config_replace('/etc/ipsec.secrets','''# Test config
: RSA hostakey.pem
''')

        elif test_type == 'ike2cert':
            testlib.config_replace('/etc/ipsec.conf','''# Test config
config setup

conn %%default
	ikelifetime=60m
	keylife=20m
	rekeymargin=3m
	keyingtries=1
	keyexchange=ikev2
	mobike=no
	
conn net-net
	left=%s
	leftcert=hostacert.pem
	leftsubnet=%s/%s
	leftid=@leftgw
	leftfirewall=yes
	right=%s
	rightsubnet=%s/%s
	rightid=@rightgw
	auto=add

''' % (self.ip_local,
       self.net_local, self.netmask_local,
       self.ip_remote,
       self.net_remote, self.netmask_remote))

            testlib.config_replace('/etc/ipsec.secrets','''# Test config
: RSA hostakey.pem
''')

        # Use the same static certs for both sides of the tunnel
        # to simplify running this script on two different servers
        #
        # These certs were generated with following commands:
        #
        # Generate the CA:
        # openssl genrsa -out cakey.pem 2048
        # openssl req -new -x509 -nodes -sha1 -days 5000 -key cakey.pem \
        # -subj /C=US/ST=Arizona/O=Testlib/OU=Test/CN=CA -out cacert.pem
        #
        # ln -s cacert.pem `openssl x509 -noout -hash -in cacert.pem`.0
        #
        # Cert for Client:
        # openssl req -newkey rsa:1024 -sha1 -days 5000 -nodes -keyout \
        # hostakey.pem -out hostareq.pem -subj /C=US/ST=Arizona/O=Testlib/OU=Test/CN=hosta
        #
        # openssl x509 -req -in hostareq.pem -days 5000 -sha1 -CA cacert.pem \
        # -CAkey cakey.pem -set_serial 01 -out hostacert.pem

        testlib.config_replace('/etc/ipsec.d/certs/5a23788d.0',
'''-----BEGIN CERTIFICATE-----
MIIDbTCCAlWgAwIBAgIJAIQnwC0gy/r0MA0GCSqGSIb3DQEBBQUAME0xCzAJBgNV
BAYTAlVTMRAwDgYDVQQIDAdBcml6b25hMRAwDgYDVQQKDAdUZXN0bGliMQ0wCwYD
VQQLDARUZXN0MQswCQYDVQQDDAJDQTAeFw0xNTA1MjkxMzU4MjNaFw0yOTAyMDQx
MzU4MjNaME0xCzAJBgNVBAYTAlVTMRAwDgYDVQQIDAdBcml6b25hMRAwDgYDVQQK
DAdUZXN0bGliMQ0wCwYDVQQLDARUZXN0MQswCQYDVQQDDAJDQTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMq/39Ulya1cFRcoU1kmI1ZtyeoMxl/GS64y
zZAY5WX0OS0EJ7S8E1ALpFm6DjcbGmCsh0FBCKD47VQi0APK/lB3KQSG3fovA+kR
7sOWideAl2T/LDas/+UxAJ4eAzFoV4D/zQycKpxho5H1gFbx8l8hAmo8KDVAUzRn
Sk/a1kJ7V2WzzumbVqYwnZWWKfEnfzdHvhIbM4J3ChIbg3isD27MODHrKM9izud4
+h5ikvX+0EHvQk1GRn8vTbQaEA51mdzqxiMWU/9Puuh9575UKEubkMBez2dfTO2A
wZ5UN9KOqwJjGDqm7udoYEVYRuyfKY8hdPWWyVRhXwBAYdbC6TUCAwEAAaNQME4w
HQYDVR0OBBYEFIH/2SOMgc0sm7MrmYfSDSm3AiLRMB8GA1UdIwQYMBaAFIH/2SOM
gc0sm7MrmYfSDSm3AiLRMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEB
ADE2csdxcwgVkLPlr3/cypkuNFrbQHB4vwRVUS87uQ7/vKzp+Wasn0k7speyiTFQ
nITVD6U3riVuoPhdVUC35WJLgIJbxNU4wjwXWtrzlBGZ8gatYdH86oADdXmmWYt8
eGukA/Z67cjTARnKC1GO8drrJ3FNAMCy2aDifueRbJhO7Eyok4ur7QcktBZ4TPVm
rwmiBonAjuFMcFEaQam8rjdS5YBItdMu3DqQXAUHhaZ6Kww8jkIxBhW/gHrWOJLb
wSebnFFif9dWq+44VkDxqlquQqEvE1cztzjalDhxFwzdzqCH0XDbrDy6JDhKcpBF
CTyJNNseEBx0O9XmvmYlZ3o=
-----END CERTIFICATE-----''')

        testlib.config_replace('/etc/ipsec.d/certs/hostacert.pem',
'''-----BEGIN CERTIFICATE-----
MIICjTCCAXUCAQEwDQYJKoZIhvcNAQEFBQAwTTELMAkGA1UEBhMCVVMxEDAOBgNV
BAgMB0FyaXpvbmExEDAOBgNVBAoMB1Rlc3RsaWIxDTALBgNVBAsMBFRlc3QxCzAJ
BgNVBAMMAkNBMB4XDTE1MDUyOTEzNTkzNFoXDTI5MDIwNDEzNTkzNFowUDELMAkG
A1UEBhMCVVMxEDAOBgNVBAgMB0FyaXpvbmExEDAOBgNVBAoMB1Rlc3RsaWIxDTAL
BgNVBAsMBFRlc3QxDjAMBgNVBAMMBWhvc3RhMIGfMA0GCSqGSIb3DQEBAQUAA4GN
ADCBiQKBgQC6juz8j1iUb4jmTXGKvOFmCLXelq8keHK8obPoQjaADZL2EeQqGU88
dPNoXTROdr5WJhgqwRt4UE8TvGNjULtuFlMFE97SzGE/MU3Opc/QzZKAlhjkE1nK
D+AXPcp/FMitGAWsxVGWiX64l9wtur3jAHgdoitPds1kSNNxbe99RQIDAQABMA0G
CSqGSIb3DQEBBQUAA4IBAQAPllPcngLy+/yMhbkWzZGxBrMuM3GfCDw+CZGkE/5V
XiB5021bRrpkzvTSjWTu2S7SxGmcuz+iUMTaz+TpTMa1KDYXN8Hvh7QomlYwVlr5
s2YgKkNPVdBAh7mn9CZ8Fu+987KRcyW05oly6al+jAJnScTyMCtWzp1qpsPMOsrK
db1HCTYHUwo8iT8XMaGkk4ZmDGL1MHojDh/jqxtipL39LJeFKUbWPHWgwcQ10nQk
ZCBh6NkEOz4GyL95jZUrW83IilTSCu1SfKQSG8UKKZJVbsOoGmMIgNWy+r0xKsP+
u5B/OUmw8K6MHdzgvyVp5qjVljqfBlUBsmm8TkfMbR61
-----END CERTIFICATE-----''')

        testlib.config_replace('/etc/ipsec.d/certs/hostakey.pem',
'''-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALqO7PyPWJRviOZN
cYq84WYItd6WryR4cryhs+hCNoANkvYR5CoZTzx082hdNE52vlYmGCrBG3hQTxO8
Y2NQu24WUwUT3tLMYT8xTc6lz9DNkoCWGOQTWcoP4Bc9yn8UyK0YBazFUZaJfriX
3C26veMAeB2iK092zWRI03Ft731FAgMBAAECgYAPykcevVdHAQW6UHW6w2/kffo+
w8xBLvyvIJSkpO4N+pgkwbDpK0k8mb18aN8jgQNtMT48aCnWDh4TUo+q+UtTyciJ
zwnJqzedbVm3nkLpqkNAN1HAOjln9FoPomymU0NgigmQqTudteeOA6qn3GcVCwUK
QHmewAbvfU3WHF6WwQJBAPYXHnxiFLtdHPrxuBc9gr9h6OnC4ItfvAVI2MG5/3da
i9qlLTYrIjBGohXyayGAFP3bgjdm4exEC4MxhJJzjbUCQQDCEhtQ2T4irc0oUriM
VO1oMDN/wW2iNR62jImkbvs2KGeZ29+/UbNd6gzaB99ZGBQntp+vci0hazuATG8t
sWtRAkEAwsNxYUfO2KrM8N61r88C160JxVhyllviVtxckJZAVZnX7eekbKaenE6K
oYwGtbDE7FT6LhbC31bLNb3PColhsQJALxh1yIjvqzrCLqbkYim58y6/UKGAGX0K
lwJD5MOJ8vqbKZtSEPuiq4fA1qhSayyMt5Z56fmrOhDrv5bM5CnKAQJBAMSlGYIt
3QpckAAMz/WmJcyEvTTCQhOkFG8VC7Y/25nru8irgJCyL1V9xgZrO1DODsz5xnMG
H0jOhDdJBKpns4w=
-----END PRIVATE KEY-----''')

        # Start daemons
        if self.lsb_release['Release'] >= 15.04:
            self.assertShellExitEquals(0,['systemctl', 'start','strongswan'])
        else:
            self.assertShellExitEquals(0,['start','strongswan'])

        global daemons_okay
        daemons_okay = True

    def _ip_alive(self, ip, count=1, timeout=5):
        '''Pings a remote host, returns (exit code, output)'''

        return testlib.cmd(['ping','-n','-c','%d' % (count),'-w','%d' % (timeout),'--',ip])

    def _test_ip_alive(self, ip, msg, max=1, timeout=1):
        '''Tries to ping repeatedly for an IP'''
        count = 0
        rc = 1
        output = None
        while count < max and rc != 0:
            if count != 0:
                time.sleep(1)
            rc, output = self._ip_alive(ip, timeout=timeout)
            count = count + 1
        self.assertEqual(rc, 0, 'Failed to reach %s (%s):\n%s' % (msg, ip, output))

    def test_01_wait_for_remote_gateway(self):
        '''Remote gateway is pingable'''
        self._test_ip_alive(self.ip_remote, 'remote gateway', max=2, timeout=4)

    def test_02_wait_for_remote_network(self):
        '''Remote tunnelled network is pingable'''
        global daemons_okay
        self.assertTrue(daemons_okay, "Network tunnel was not configured")
        self._test_ip_alive(self.net_ip_remote, 'remote tunnelled network', max=20, timeout=4)

    # This can cause problems when the local and remote aren't well-synchrnoized
    def test_99_shutdown(self):
        '''Shutting down'''

        # Wait for remote end to finish pings
        time.sleep(5)
        if self.lsb_release['Release'] >= 15.04:
            self.assertShellExitEquals(0,['systemctl', 'stop','strongswan'])
        else:
            self.assertShellExitEquals(0,['stop','strongswan'])

        self.assertShellExitEquals(0,['ifconfig','%s:test' % (self.iface),'down'])

if __name__ == '__main__':
    testlib.require_sudo()
    # FIXME: is global configuration the only way to do this?
    try:
        iface = None
        test_type = sys.argv.pop(1)
        if test_type not in ["ike1psk", "ike1cert", "ike2psk", "ike2cert"]:
            raise

        ip_local   = sys.argv.pop(1)
        net_local  = sys.argv.pop(1)
        ip_remote  = sys.argv.pop(1)
        net_remote = sys.argv.pop(1)
    except:
        print >>sys.stderr, "Usage: %s ike1psk|ike1cert|ike2psk|ike2cert LOCAL_IP LOCAL_NET/MASK REMOTE_IP REMOTE_NET/MASK [OPTIONS]" % (sys.argv[0])
        sys.exit(1)

    unittest.main()
