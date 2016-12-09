#!/usr/bin/python
#
#    test-python.py quality assurance test script
#    Copyright (C) 2009-2015 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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

'''
    How to run against a clean schroot named 'hardy':
      python 2.4:
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release python2.4 && ./test-python.py python2.4 -v'

      python 2.5:
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release python2.5 && ./test-python.py python2.5 -v'

      python 2.6:
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release python2.6 && ./test-python.py python2.6 -v'


    How to run against a clean schroot named 'oneiric':
      python 3.1:
        schroot -c oneiric -u root -- sh -c 'apt-get -y install lsb-release python3.1 && ./test-python.py python3.1 -v'

      python 3.2:
        schroot -c oneiric -u root -- sh -c 'apt-get -y install lsb-release python3.2 && ./test-python.py python3.2 -v'

      python 3.2:
        schroot -c oneiric -u root -- sh -c 'apt-get -y install lsb-release python3.3 && ./test-python.py python3.3 -v'
'''

# QRT-Depends: data

import unittest, tempfile, os, sys
import testlib
import time
import __builtin__
import shutil

exe = ""
proxy = ""
orig_symlinks = []

use_private = True
try:
    from private.qrt.python import PythonPrivateTests
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class PythonTest(testlib.TestlibCase):
    '''Test python.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.fs_dir = os.path.abspath('.')
        self.pythonscript = tempfile.NamedTemporaryFile(suffix='.py',prefix='python-test-')
        os.chmod(self.pythonscript.name,0700)
        self.tempdir = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.pythonscript = None

        os.chdir(self.fs_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)
        if os.path.exists('/tmp/x'):
            os.unlink('/tmp/x')

    def _get_print_statement(self, s):
        '''Return print statement depending on python2 vs python3'''
        if "python3" in exe:
            return 'print(%s, file=sys.stdout)' % s
        return 'print %s' % s

    def _run_script(self, contents, expected=0, args=[]):
        handle, name = testlib.mkstemp_fill(contents)
        self.assertShellExitEquals(expected, ['/usr/bin/%s' %(exe)] + args, stdin = handle)
        os.unlink(name)

    def test_symlink_without_dir(self):
        '''Does not unpack through symlink to non-existing directory'''

        expected = 0
        if "python2.7" in exe and self.lsb_release['Release'] >= 11.04:
            expected = 1
        elif "python3.2" in exe:
            expected = 1
        elif "python3.3" in exe:
            expected = 1
        elif "python3.4" in exe:
            expected = 1

        self.tempdir = tempfile.mkdtemp(prefix='test-python-')
        os.chdir(self.tempdir)
        self._run_script('''
import sys, tarfile

tar = tarfile.open('%s/data/bad-symlink-following-without-dir.tar')
tar.ignore_zeros = True
for tarinfo in tar:
    tar.extract(tarinfo, '.')
tar.close()
sys.exit(0)
''' % (self.fs_dir), expected=expected)
        self.assertTrue(os.path.exists('linktest'))
        self.assertFalse(os.path.exists('linktest/link'))
        self.assertFalse(os.path.exists('linktest/orig/x'))

    def test_symlink_with_internal_dir(self):
        '''Unpacks through symlink to directory from archive'''
        self.tempdir = tempfile.mkdtemp(prefix='test-python-')
        os.chdir(self.tempdir)
        self._run_script('''
import sys, tarfile

tar = tarfile.open('%s/data/bad-symlink-following-with-dir.tar')
tar.ignore_zeros = True
for tarinfo in tar:
    tar.extract(tarinfo, '.')
tar.close()
sys.exit(0)
''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/link'))
        # tar safely handles non-relative paths with symlinks
        self.assertTrue(os.path.exists('linktest/orig/x'))

    def test_symlink_with_external_dir(self):
        '''Does not unpack through symlink to directory outside of archive (CVE-2007-4559)'''
        self._skipped("Not fixed upstream")
        expected = True

        self.tempdir = tempfile.mkdtemp(prefix='test-python-')
        os.chdir(self.tempdir)
        self.assertFalse(os.path.exists('/tmp/x'))
        self._run_script('''
import sys, tarfile

tar = tarfile.open('%s/data/bad-symlink-following-absolute-path.tar')
tar.ignore_zeros = True
for tarinfo in tar:
    tar.extract(tarinfo, '.')
tar.close()
sys.exit(0)
''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/link'))
        self.assertEquals(expected, os.path.exists('/tmp/x'))

    def test_symlink_to_dotdot(self):
        '''Does not unpack through symlink to dot dot (CVE-2007-4559)'''
        self._skipped("Not fixed upstream")
        expected = True

        self.tempdir = tempfile.mkdtemp(prefix='test-python-')
        os.chdir(self.tempdir)
        os.mkdir('deeper')
        os.chdir('deeper')
        self._run_script('''
import sys, tarfile

tar = tarfile.open('%s/data/bad-symlink-following-with-dotdot.tar')
tar.ignore_zeros = True
for tarinfo in tar:
    tar.extract(tarinfo, '.')
tar.close()
sys.exit(0)
''' % (self.fs_dir))
        self.assertTrue(os.path.exists('linktest'))
        self.assertTrue(os.path.exists('linktest/evil'))
        self.assertEquals(expected, os.path.exists('../zomg'))

    def test_verify_CVE_2008_4864(self):
        '''Verify CVE-2008-4864'''

        if "python3" in exe:
            return self._skipped("imageop module doesn't exist in python3")
        if self.dpkg_arch == 'amd64':
            return self._skipped("imageop module doesn't exist on amd64")

        # Taken from here: http://svn.python.org/view?view=rev&revision=66689
        # and here: http://svn.python.org/view?view=rev&revision=67270
        self.pythonscript.write('''#!/usr/bin/%s
import imageop
SIZES = (1, 2, 3, 4)
_VALUES = (1, 2, 2**10, 2**15-1, 2**15, 2**15+1, 2**31-2, 2**31-1)
VALUES = tuple( -x for x in reversed(_VALUES) ) + (0,) + _VALUES
AAAAA = "A" * 1024
MAX_LEN = 2**20

def _check(name, size=None, *extra):
    func = getattr(imageop, name)
    for height in VALUES:
        for width in VALUES:
            strlen = abs(width * height)
            if size:
                strlen *= size
            if strlen < MAX_LEN:
                data = "A" * strlen
            else:
                data = AAAAA
            if size:
                arguments = (data, size, width, height) + extra
            else:
                arguments = (data, width, height) + extra
            try:
                func(*arguments)
            except (ValueError, imageop.error):
                pass

def check_size(name, *extra):
    for size in SIZES:
        _check(name, size, *extra)

def check(name, *extra):
    _check(name, None, *extra)

check_size("crop", 0, 0, 0, 0)
check_size("scale", 1, 0)
check_size("scale", -1, -1)
check_size("tovideo")
check("grey2mono", 128)
check("grey2grey4")
check("grey2grey2")
check("dither2mono")
check("dither2grey2")
check("mono2grey", 0, 0)
check("grey22grey")
check("rgb2rgb8") # nlen*4 == len
check("rgb82rgb")
check("rgb2grey")
check("grey2rgb")
''' % (exe))
        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_verify_CVE_2013_2099(self):
        '''Verify CVE-2013-2099'''

        if self.lsb_release['Release'] < 13.04 and "python2" in exe:
            return self._skipped("match_hostname doesn't exist")

        # Taken from here: http://hg.python.org/cpython/rev/c627638753e2
        self.pythonscript.write('''#!/usr/bin/%s

import ssl,sys

def ok(cert, hostname):
    ssl.match_hostname(cert, hostname)

def fail(cert, hostname):
    try:
        ssl.match_hostname(cert, hostname)
    except:
        return
    sys.exit(1)

cert = {'subject': ((('commonName', 'a*b.com'),),)}
ok(cert, 'axxb.com')
cert = {'subject': ((('commonName', 'a*b*.com'),),)}
fail(cert, 'axxbxxc.com')

''' % (exe))
        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_verify_CVE_2014_4616(self):
        '''Verify CVE-2014-4616'''

        # Taken from here: http://bugs.python.org/issue21529
        self.pythonscript.write('''#!/usr/bin/%s

import sys
from json import JSONDecoder
j = JSONDecoder()

a = '128931233'
b = "472389423"

if id(a) < id(b):
    x = a
    y = b
else:
    x = b
    y = a

diff = id(x) - id(y)

try:
    j.raw_decode(y, diff)
    print("Vulnerable")
    sys.exit(1)
except:
    print("Not vulnerable")
    sys.exit(0)

''' % (exe))
        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_verify_CVE_2014_1912(self):
        '''Verify CVE-2014-1912'''

        if "python2.6" in exe:
            self.pythonscript.write('''#!/usr/bin/%s

import socket,sys,array

s1, s2 = socket.socketpair()

text = 'Ubuntu rocks!'

s1.send(text)
bufA = array.array('b', 'x' * 80)
(nbytes, address) = s2.recvfrom_into(bufA, 80)
if not text in bufA.tostring():
    sys.exit(2)

s1.send(text)
bufB = array.array('b', 'x' * 8)
try:
    (nbytes, address) = s2.recvfrom_into(bufB, 80)
except:
    sys.exit(0)

sys.exit(1)
''' % (exe))
        else:
            self.pythonscript.write('''#!/usr/bin/%s

import socket,sys

s1, s2 = socket.socketpair()

text = b'Ubuntu rocks!'

s1.send(text)
bufA = bytearray(80)
(nbytes, address) = s2.recvfrom_into(bufA, 80)
if not text in bufA:
    sys.exit(2)

s1.send(text)
bufB = bytearray(8)
try:
    (nbytes, address) = s2.recvfrom_into(bufB, 80)
except:
    sys.exit(0)

sys.exit(1)
''' % (exe))

        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_verify_CVE_2013_4238_1(self):
        '''Verify CVE-2013-4238 (Test 1)'''
        # Taken from here: http://hg.python.org/cpython/rev/c9f073e593b0
        cert = '''-----BEGIN CERTIFICATE-----
MIIE2DCCA8CgAwIBAgIBADANBgkqhkiG9w0BAQUFADCBxTELMAkGA1UEBhMCVVMx
DzANBgNVBAgMBk9yZWdvbjESMBAGA1UEBwwJQmVhdmVydG9uMSMwIQYDVQQKDBpQ
eXRob24gU29mdHdhcmUgRm91bmRhdGlvbjEgMB4GA1UECwwXUHl0aG9uIENvcmUg
RGV2ZWxvcG1lbnQxJDAiBgNVBAMMG251bGwucHl0aG9uLm9yZwBleGFtcGxlLm9y
ZzEkMCIGCSqGSIb3DQEJARYVcHl0aG9uLWRldkBweXRob24ub3JnMB4XDTEzMDgw
NzEzMTE1MloXDTEzMDgwNzEzMTI1MlowgcUxCzAJBgNVBAYTAlVTMQ8wDQYDVQQI
DAZPcmVnb24xEjAQBgNVBAcMCUJlYXZlcnRvbjEjMCEGA1UECgwaUHl0aG9uIFNv
ZnR3YXJlIEZvdW5kYXRpb24xIDAeBgNVBAsMF1B5dGhvbiBDb3JlIERldmVsb3Bt
ZW50MSQwIgYDVQQDDBtudWxsLnB5dGhvbi5vcmcAZXhhbXBsZS5vcmcxJDAiBgkq
hkiG9w0BCQEWFXB5dGhvbi1kZXZAcHl0aG9uLm9yZzCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALXq7cn7Rn1vO3aA3TrzA5QLp6bb7B3f/yN0CJ2XFj+j
pHs+Gw6WWSUDpybiiKnPec33BFawq3kyblnBMjBU61ioy5HwQqVkJ8vUVjGIUq3P
vX/wBmQfzCe4o4uM89gpHyUL9UYGG8oCRa17dgqcv7u5rg0Wq2B1rgY+nHwx3JIv
KRrgSwyRkGzpN8WQ1yrXlxWjgI9de0mPVDDUlywcWze1q2kwaEPTM3hLAmD1PESA
oY/n8A/RXoeeRs9i/Pm/DGUS8ZPINXk/yOzsR/XvvkTVroIeLZqfmFpnZeF0cHzL
08LODkVJJ9zjLdT7SA4vnne4FEbAxDbKAq5qkYzaL4UCAwEAAaOB0DCBzTAMBgNV
HRMBAf8EAjAAMB0GA1UdDgQWBBSIWlXAUv9hzVKjNQ/qWpwkOCL3XDALBgNVHQ8E
BAMCBeAwgZAGA1UdEQSBiDCBhYIeYWx0bnVsbC5weXRob24ub3JnAGV4YW1wbGUu
Y29tgSBudWxsQHB5dGhvbi5vcmcAdXNlckBleGFtcGxlLm9yZ4YpaHR0cDovL251
bGwucHl0aG9uLm9yZwBodHRwOi8vZXhhbXBsZS5vcmeHBMAAAgGHECABDbgAAAAA
AAAAAAAAAAEwDQYJKoZIhvcNAQEFBQADggEBAKxPRe99SaghcI6IWT7UNkJw9aO9
i9eo0Fj2MUqxpKbdb9noRDy2CnHWf7EIYZ1gznXPdwzSN4YCjV5d+Q9xtBaowT0j
HPERs1ZuytCNNJTmhyqZ8q6uzMLoht4IqH/FBfpvgaeC5tBTnTT0rD5A/olXeimk
kX4LxlEx5RAvpGB2zZVRGr6LobD9rVK91xuHYNIxxxfEGE8tCCWjp0+3ksri9SXx
VHWBnbM9YaL32u3hxm8sYB/Yb8WSBavJCWJJqRStVRHM1koZlJmXNx2BX4vPo6iW
RFEIPQsFZRLrtnCAiEhyT8bC2s/Njlu6ly9gtJZWSV46Q3ZjBL4q9sHKqZQ=
-----END CERTIFICATE-----
'''

        self.tempdir = tempfile.mkdtemp(prefix='test-python-')
        _handle, tmpname = testlib.mkstemp_fill(cert, dir=self.tempdir)

        self.pythonscript.write(r'''#!/usr/bin/%s

import ssl,sys

p = ssl._ssl._test_decode_cert('%s')

subject = ((('countryName', 'US'),),
           (('stateOrProvinceName', 'Oregon'),),
           (('localityName', 'Beaverton'),),
           (('organizationName', 'Python Software Foundation'),),
           (('organizationalUnitName', 'Python Core Development'),),
           (('commonName', 'null.python.org\x00example.org'),),
           (('emailAddress', 'python-dev@python.org'),))

if p['subject'] != subject:
    sys.exit(1)

if p['issuer'] != subject:
    sys.exit(1)

san = (('DNS', 'altnull.python.org\x00example.com'),
       ('email', 'null@python.org\x00user@example.org'),
       ('URI', 'http://null.python.org\x00http://example.org'),
       ('IP Address', '192.0.2.1'),
       ('IP Address', '2001:DB8:0:0:0:0:0:1\n'))

if p['subjectAltName'] != san:
    sys.exit(1)

''' % (exe, tmpname))
        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_verify_CVE_2013_4238_2(self):
        '''Verify CVE-2013-4238 (Test 2)'''
        # Taken from here: http://hg.python.org/cpython/rev/c9f073e593b0

        if self.lsb_release['Release'] < 13.04 and "python2" in exe:
            return self._skipped("match_hostname doesn't exist")

        self.pythonscript.write(r'''#!/usr/bin/%s

import ssl,sys

def ok(cert, hostname):
    ssl.match_hostname(cert, hostname)

def fail(cert, hostname):
    try:
        ssl.match_hostname(cert, hostname)
    except:
        return
    sys.exit(1)

cert = {'subject': ((('commonName',
                      'null.python.org\x00example.org'),),)}
ok(cert, 'null.python.org\x00example.org')
fail(cert, 'example.org')
fail(cert, 'null.python.org')

''' % (exe))
        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_verify_CVE_2008_5031(self):
        '''Verify CVE-2008-5031'''

        if self.dpkg_arch == 'amd64':
            return self._skipped("expandtabs doesn't overflow on amd64")

        # Taken from here: http://svn.python.org/view?view=rev&revision=67270
        self.pythonscript.write('''#!/usr/bin/%s
import sys
s = 't\tt\t'
str.expandtabs(s, sys.maxint)
''' % (exe))
        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_expat(self):
        '''Test expat'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="expat-")
        version = "20080827"
        shutil.copy('./data/xmlts%s.tar.gz' % version, self.tempdir)
        os.chdir(self.tempdir)
        (rc, report) = testlib.cmd(["tar", "zxf", 'xmlts%s.tar.gz' % version])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

	# This script mimics xmlwf and will exit 0 if the script runs without
        # problems. Will have to check for failures in the script output.
        self.pythonscript.write('''#!/usr/bin/%s
# from http://docs.python.org/library/pyexpat.html
import xml.parsers.expat
import glob
import os
import sys

tempdir = "%s"

def start_element(name, attrs):
    assert(name)
def end_element(name):
    assert(name)
def char_data(data):
    assert(data)

topdir = os.path.join(tempdir, "xmlconf")
well_formed = []
for g in ['ibm/valid/P*', 'ibm/invalid/P*']:
    well_formed += glob.glob(os.path.join(topdir, g))

for d in ['xmltest/valid/ext-sa', 'xmltest/valid/not-sa', 'xmltest/invalid', 'xmltest/invalid/not-sa', 'xmltest/valid/sa', 'sun/valid', 'sun/invalid']:
    well_formed.append(os.path.join(topdir, d))

count = 0
passed = 0
failures = 0

%s # print "Well-formed:"
for d in well_formed:
    for f in os.listdir(d):
        #if not f.endswith('.xml'):
        if not f.endswith('.xml') and not f.endswith('.html'):
            continue

        # Due to http://bugs.python.org/issue6676, we have to
        # ParserCreate on each file
        p = xml.parsers.expat.ParserCreate()

        p.StartElementHandler = start_element
        p.EndElementHandler = end_element
        p.CharacterDataHandler = char_data

        p.UseForeignDTD(True)
        try:
            p.Parse(open(os.path.join(d, f)).read())
            passed += 1
        except:
            failures += 1
            %s # print "  " + os.path.join(d.split(topdir)[1], f) + ": FAIL"
        p = None
        count += 1
if failures == 0:
    %s # print "  pass"

not_well_formed = []
for g in ['ibm/not-wf/P*']:
    not_well_formed += glob.glob(os.path.join(topdir, g))

for d in ['ibm/not-wf/misc', 'xmltest/not-wf/ext-sa', 'xmltest/not-wf/not-sa', 'xmltest/not-wf/sa', 'sun/not-wf']:
    not_well_formed.append(os.path.join(topdir, d))

prev_failures = failures
%s # print "Not well-formed:"
for d in not_well_formed:
    for f in os.listdir(d):
        if not f.endswith('.xml') and not f.endswith('.html'):
            continue

        p = xml.parsers.expat.ParserCreate()
        p.StartElementHandler = start_element
        p.EndElementHandler = end_element
        p.CharacterDataHandler = char_data

        p.UseForeignDTD(True)

        try:
            p.Parse(open(os.path.join(d, f)).read())
            failures += 1
            %s # print "  " + os.path.join(d.split(topdir)[1], f) + ": FAIL"
        except:
            passed += 1
        p = None
        count += 1

if failures == prev_failures:
    %s # print "  pass"

%s # print "XML files processed: " + str(count) + " (" + str(passed) + " passed, " + str(failures) + " failed)"

''' % (exe, self.tempdir,
       self._get_print_statement('"Well-formed:"'),
       self._get_print_statement('"  " + os.path.join(d.split(topdir)[1], f) + ": FAIL"'),
       self._get_print_statement('"  pass"'),
       self._get_print_statement('"Not well-formed:"'),
       self._get_print_statement('"  " + os.path.join(d.split(topdir)[1], f) + ": FAIL"'),
       self._get_print_statement('"  pass"'),
       self._get_print_statement('"XML files processed: " + str(count) + " (" + str(passed) + " passed, " + str(failures) + " failed)"')))

        self.pythonscript.flush()

        (rc, report) = testlib.cmd([exe, self.pythonscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

	# There are a lot of expected failures because pyexpat is a
        # non-validating parser. All we are really trying to do here
        # is detect changes in the parser and crashes (there should
        # of course be no crashes, and the script will exit non-zero
        # if crash). Known to work with python 2.4-2.7 and 3.1-3.2.
        expected_output = []
        if "python3" in exe:
            expected_output.append("/xmltest/valid/sa/049.xml: FAIL")
            expected_output.append("/xmltest/valid/sa/051.xml: FAIL")
            expected_output.append("/xmltest/valid/sa/050.xml: FAIL")
            expected_output.append("/sun/invalid/utf16l.xml: FAIL")
            expected_output.append("/sun/invalid/utf16b.xml: FAIL")
        expected_output.append("/ibm/not-wf/P01/ibm01n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P78/ibm78n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P78/ibm78n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P69/ibm69n05.xml: FAIL")
        expected_output.append("/ibm/not-wf/P77/ibm77n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P77/ibm77n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P77/ibm77n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P77/ibm77n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P31/ibm31n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P23/ibm23n05.xml: FAIL")
        expected_output.append("/ibm/not-wf/P79/ibm79n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P79/ibm79n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n08.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n06.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n07.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n05.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P62/ibm62n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P30/ibm30n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P18/ibm18n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P42/ibm42n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P64/ibm64n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P64/ibm64n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P64/ibm64n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P61/ibm61n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P28/ibm28n08.xml: FAIL")
        expected_output.append("/ibm/not-wf/P68/ibm68n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P68/ibm68n05.xml: FAIL")
        expected_output.append("/ibm/not-wf/P11/ibm11n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P11/ibm11n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P12/ibm12n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P12/ibm12n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P16/ibm16n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P16/ibm16n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P09/ibm09n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P65/ibm65n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P65/ibm65n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n05.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n07.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n06.xml: FAIL")
        expected_output.append("/ibm/not-wf/P63/ibm63n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P29/ibm29n05.xml: FAIL")
        expected_output.append("/ibm/not-wf/P29/ibm29n06.xml: FAIL")
        expected_output.append("/ibm/not-wf/P15/ibm15n02.xml: FAIL")
        expected_output.append("/ibm/not-wf/P15/ibm15n04.xml: FAIL")
        expected_output.append("/ibm/not-wf/P39/ibm39n01.xml: FAIL")
        expected_output.append("/ibm/not-wf/P39/ibm39n03.xml: FAIL")
        expected_output.append("/ibm/not-wf/misc/432gewf.xml: FAIL")
        expected_output.append("/xmltest/not-wf/ext-sa/002.xml: FAIL")
        expected_output.append("/xmltest/not-wf/ext-sa/001.xml: FAIL")
        expected_output.append("/xmltest/not-wf/ext-sa/003.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/002.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/011.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/001.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/010.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/008.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/004.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/005.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/003.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/009.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/007.xml: FAIL")
        expected_output.append("/xmltest/not-wf/not-sa/006.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/076.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/072.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/017.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/050.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/028.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/179.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/004.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/005.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/073.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/176.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/027.xml: FAIL")
        expected_output.append("/xmltest/not-wf/sa/077.xml: FAIL")
        expected_output.append("/sun/not-wf/encoding07.xml: FAIL")
        expected_output.append("/sun/not-wf/uri01.xml: FAIL")
        expected_output.append("/sun/not-wf/cond01.xml: FAIL")
        expected_output.append("/sun/not-wf/sgml01.xml: FAIL")
        expected_output.append("/sun/not-wf/decl01.xml: FAIL")
        expected_output.append("/sun/not-wf/element01.xml: FAIL")
        expected_output.append("/sun/not-wf/cond02.xml: FAIL")
        expected_output.append("/sun/not-wf/element00.xml: FAIL")
        expected_output.append("/sun/not-wf/dtd07.xml: FAIL")
        if "python3" in exe:
            expected_output.append("XML files processed: 1460 (1367 passed, 93 failed)")
        else:
            expected_output.append("XML files processed: 1460 (1372 passed, 88 failed)")
        result = ""
        for line in expected_output:
            if line not in report:
                result += "Couldn't find '%s' in report\n" % (line)
        self.assertTrue(result == "", result + report + '\nThis script is known to work with python 2.4-2.7 and 3.1-3.2')

        #print report

    def _test_crypt(self, passwd, salt, expected):
        '''helper crypt test function'''
        self._run_script('''
import sys, crypt
expected = '%s'
result = crypt.crypt('%s', '%s')
if result != expected:
    %s # print "Expected: " + expected + "; Result: " + result
    sys.exit(1)
''' % (expected, passwd, salt,
       self._get_print_statement('"Expected: " + expected + "; Result: " + result')))

    def test_crypt_des(self):
        '''Test crypt des returns sane results'''
        expected = 'sl0N1Oj5JS0pw'
        self._test_crypt('password', 'sl', expected)

    def test_crypt_md5(self):
        '''Test crypt md5 returns sane results'''
        expected = '$1$NaCLed$SjfVY2uCnG2pboyz6m7ai.'
        self._test_crypt('password', '$1$NaCLed$', expected)

    def test_crypt_sha256(self):
        '''Test crypt sha256 returns sane results'''
        expected = '$5$NaCLed$Cqj.S6IfGEOQZQWxweDbd8BEB57Dl9mSRLqXAqmrXc.'
        self._test_crypt('password', '$5$NaCLed$', expected)

    def test_crypt_sha256_rounds(self):
        '''Test crypt sha256 with rounds arg returns sane results'''
        expected = '$5$rounds=2038$NaCLed$Ww4ugTHG34ahBTTjT/QuiTp6njEFmpK3iX6vJirL601'
        self._test_crypt('password', '$5$rounds=2038$NaCLed$', expected)

    def test_crypt_sha256_under_1000_rounds(self):
        '''Test crypt sha256 with rounds arg < 1000 returns sane results'''

        '''if glibc implementation assumes 1000 rounds as a minimum and
           crypt results adjust the rounds value'''
        expected = '$5$rounds=1000$NaCLed$90mwj1DcQ9orN.qEI.ZeSDyny3zrWEN9XHFSKnAO/B/'
        self._test_crypt('password', '$5$rounds=238$NaCLed$', expected)
        self._test_crypt('password', '$5$rounds=438$NaCLed$', expected)
        self._test_crypt('password', '$5$rounds=1000$NaCLed$', expected)

    def test_crypt_sha512(self):
        '''Test crypt sha512 returns sane results'''
        expected = '$6$NaCLed$zZ68kP73bHoQ075Pjk0I2RJknLmAM/rtsZ.hsQ9X8Wy1mibeuyMS17EALng/WzIWwQ/Ej1xrcVN9Qz4ndlVLW1'
        self._test_crypt('password', '$6$NaCLed$', expected)

    def test_crypt_sha512_rounds(self):
        '''Test crypt sha512 with rounds arg returns sane results'''
        expected = '$6$rounds=2038$NaCLed$.AImsQ2oUS/tHrglcOh1jgzJGOzeY5LP3SMtMT.QPptBEt8e1ZvQwSTyrZltc4C7.K9xcM7PN4Q5OMaEAsS9D0'
        self._test_crypt('password', '$6$rounds=2038$NaCLed$', expected)

    def test_crypt_sha512_under_1000_rounds(self):
        '''Test crypt sha512 with rounds arg < 1000 returns sane results'''

        '''if glibc implementation assumes 1000 rounds as a minimum and
           crypt results adjust the rounds value'''
        expected = '$6$rounds=1000$NaCLed$sQYIVIMT26G0SOuyzy4pe5tR.SatQAo/B1jEyMvNdmXHZBZ0H6ImF1fanLhVpLq1x75IJXUfinN6F4STu6od3.'
        self._test_crypt('password', '$6$rounds=237$NaCLed$', expected)
        self._test_crypt('password', '$6$rounds=437$NaCLed$', expected)
        self._test_crypt('password', '$6$rounds=1000$NaCLed$', expected)

    def test_urllib_schemes(self):
        '''Test urllib schemes (no proxy)'''
        if "python2" in exe:
            return self._skipped("urllib.request does not exist with python2")

        for u in ['http://www.python.org/', 'file:///etc/hosts']:
            self._run_script('''
import urllib.request
opener = urllib.request.FancyURLopener({})
f = opener.open("%s")
f.read()
''' % (u))

    def test_urllib_schemes_proxy(self):
        '''Test urllib schemes (proxy)'''
        if "python2" in exe:
            return self._skipped("urllib.request does not exist with python2")

        if proxy == "":
            return self._skipped("proxy not defined")

        # NOTE: this only hits the proxy for the http:// url
        for u in ['http://www.python.org/', 'file:///etc/hosts']:
            self._run_script('''
import urllib.request
proxies = {'http': '%s'}
opener = urllib.request.FancyURLopener(proxies)
f = opener.open("%s")
f.read()
''' % (proxy, u))

    def test_smtpd(self):
        '''Test smtpd'''

        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec %s -m smtpd -n >/dev/null 2>&1' % exe]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(2)
        self._run_script('''
import smtplib
s = smtplib.SMTP('127.0.0.1', 8025)
s.helo('me')
s.quit()
''')
        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

    def test_verify_CVE_2012_0845(self):
        '''Verify CVE-2012-0845'''
        if "python2" in exe:
            self.pythonscript.write('''#!/usr/bin/%s
import SimpleXMLRPCServer, SocketServer
class Server(SocketServer.ThreadingMixIn, SimpleXMLRPCServer.SimpleXMLRPCServer):
  pass
Server(('0.0.0.0', 12345)).handle_request()
''' % (exe))
        else:
            self.pythonscript.write('''#!/usr/bin/%s
from xmlrpc.server import SimpleXMLRPCServer
import socketserver
class Server(socketserver.ThreadingMixIn, SimpleXMLRPCServer):
  pass
Server(('0.0.0.0', 12345)).handle_request()
''' % (exe))
        self.pythonscript.flush()

        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', '%s %s >/dev/null 2>&1' % (exe, self.pythonscript.name)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(2)

        rc = None
        report = ""
        if self.lsb_release['Release'] < 8.10:
            rc, report = testlib.cmd_pipe(['echo', '-e', 'POST /RPC2 HTTP/1.0\r\nContent-Length: 100\r\n\r\nlol bye'], ['nc', '127.0.0.1', '12345'])
        else:
            rc, report = testlib.cmd_pipe(['echo', '-e', 'POST /RPC2 HTTP/1.0\r\nContent-Length: 100\r\n\r\nlol bye'], ['nc', '-q', '1', '127.0.0.1', '12345'])

        #print report

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        # python2.4 and python2.5 display an error. The others do not, and look
        # the same whether patched or not, so skip them
        terms = []
        if exe == "python2.4":
            terms = ['HTTP/1.0 500 Internal error', 'Python/2.4']
        elif exe == "python2.5":
            terms = ['xml.parsers.expat.ExpatError', '<methodResponse>', '<fault>', 'syntax error']
        for search in terms:
            self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

    def test_xmlrpc(self):
        '''Test xmlrpc'''
        if "python2" in exe:
            self.pythonscript.write('''#!/usr/bin/%s
from SimpleXMLRPCServer import SimpleXMLRPCServer
import os

class MyServer(SimpleXMLRPCServer):
    allow_reuse_address = True

server = MyServer(('127.0.0.1', 9000), logRequests=False)

def list_contents(dir_name):
    #print 'list_contents(%%s)' %% dir_name
    return os.listdir(dir_name)

server.register_function(list_contents)
server.handle_request()
''' % (exe))
        else:
            self.pythonscript.write('''#!/usr/bin/%s
from xmlrpc.server import SimpleXMLRPCServer
import os
import sys

class MyServer(SimpleXMLRPCServer):
    allow_reuse_address = True

server = MyServer(('127.0.0.1', 9000), logRequests=False)

def list_contents(dir_name):
    return os.listdir(dir_name)

server.register_function(list_contents)
server.handle_request()
sys.exit(0)
''' % (exe))
        self.pythonscript.flush()

        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', '%s %s >/dev/null 2>&1' % (exe, self.pythonscript.name)]
            os.execv(args[0], args)
            sys.exit(0)

        contents = ""
        if "python2" in exe:
            contents = '''
import xmlrpclib
proxy = xmlrpclib.ServerProxy('http://127.0.0.1:9000')
print proxy.list_contents('/etc')
'''
        else:
            contents = '''
import xmlrpc.client
proxy = xmlrpc.client.ServerProxy('http://127.0.0.1:9000')
print(proxy.list_contents('/etc'))
'''
        handle, name = testlib.mkstemp_fill(contents)
        handle.close()

        if "python2.4" not in exe and "python2.5" not in exe:
            time.sleep(2)
        rc, report = testlib.cmd([exe, name])

        # kill server now
        os.kill(self.listener, 15)
        os.waitpid(self.listener, 0)

        # cleanup
        os.unlink(name)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'passwd'
        self.assertTrue(search in report, "Could not find '%s' in report:\n     %s" % (search, report))

    def test_verify_CVE_2012_1150(self):
        '''Verify CVE-2012-1150'''
        if "python2.5" in exe or "python2.4" in exe:
            return self._skipped("ignored python2.4 and python2.5 for this CVE")
        rc, report = testlib.cmd([exe, '-R', '-c', 'print(hash("spam"))'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        hash1 = report

        rc, report = testlib.cmd([exe, '-R', '-c', 'print(hash("spam"))'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        hash2 = report

        # verify the hash worked
        self.assertNotEqual(hash1, hash2)

        rc, report = testlib.cmd([exe, '-R', '-c', 'import sys; print(sys.flags)'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue('hash_randomization=1' in report)

    def test_verify_CVE_2011_4940(self):
        '''Verify CVE-2011-4940'''
        if "python2" not in exe:
            return self._skipped("python2 only")
        port = 8000
        contents = '''
import SimpleHTTPServer
import SocketServer
class TestServer(SocketServer.TCPServer):
    allow_reuse_address = True
PORT = %d
Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
httpd = TestServer(("", PORT), Handler)
# just handle one request then exit
httpd.handle_request()
''' % (port)
        handle, name = testlib.mkstemp_fill(contents)
        handle.close()
        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec %s %s >/dev/null 2>&1' % (exe, name)]
            os.execv(args[0], args)
            sys.exit(0)

        time.sleep(2)
        rc, report = testlib.cmd(['w3m', '-dump_head', 'http://127.0.0.1:%d' % port])
        os.unlink(name)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertTrue('charset' in report)

    def test_verify_CVE_2010_1634(self):
        '''Verify CVE-2010-1634'''
        # This should traceback with a memory error, not segfault
        self._run_script('''
import audioop
audioop.lin2lin("A"*0x40000001, 1, 4)
''', expected=1)

    def test_verify_CVE_2010_2089(self):
        '''Verify CVE-2010-2089'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        # Stolen from 2.6 test case
        INVALID_DATA = [
            ('abc', 0),
            ('abc', 2),
            ('abc', 4),
        ]
        for data, size in INVALID_DATA:
            self.pythonscript.write('''#!/usr/bin/%s
import audioop
import sys
exe = '%s'
data = '%s'
size = %d
size2 = size
state = None

try:
    audioop.getsample(data, size, 0)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.max(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.minmax(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.avg(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.rms(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.avgpp(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.maxpp(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.cross(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.mul(data, size, 1.0)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.tomono(data, size, 0.5, 0.5)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.tostereo(data, size, 0.5, 0.5)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.add(data, data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.bias(data, size, 0)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.reverse(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.lin2lin(data, size, size2)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.ratecv(data, size, 1, 1, 1, state)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.lin2ulaw(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.ulaw2lin(data, size)
    sys.exit(1)
except audioop.error:
    pass
try:
    if "python2.5" in exe:
        audioop.lin2alaw(data, size)
        sys.exit(1)
except audioop.error:
    pass
try:
    if "python2.5" in exe:
        audioop.alaw2lin(data, size)
        sys.exit(1)
except audioop.error:
    pass
try:
    audioop.lin2adpcm(data, size, state)
    sys.exit(1)
except audioop.error:
    pass
try:
    audioop.adpcm2lin(data, size, state)
    sys.exit(1)
except audioop.error:
    pass
''' % (exe, exe, data, size))
            self.pythonscript.flush()

            (rc, report) = testlib.cmd([exe, self.pythonscript.name])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)



#
# This are stolen from Lib/test/test_httpservers.py
#
from BaseHTTPServer import HTTPServer
from CGIHTTPServer import CGIHTTPRequestHandler
import CGIHTTPServer
import threading
import httplib

class NoLogRequestHandler:
    def log_message(self, *args):
        # don't write log messages to stderr
        pass

class TestServerThread(threading.Thread):
    def __init__(self, test_object, request_handler):
        threading.Thread.__init__(self)
        self.request_handler = request_handler
        self.test_object = test_object
        self.test_object.lock.acquire()
        self._stop = False

    def run(self):
        self.server = HTTPServer(('', 0), self.request_handler)
        self.test_object.PORT = self.server.socket.getsockname()[1]
        self.test_object.lock.release()
        self.server.socket.settimeout(1.0)

        while not self._stop:
            self.server.handle_request()


    def stop(self):
        self._stop = True

cgi_file1 = """\
#!%s

print "Content-type: text/html"
print
print "Hello World"
"""

cgi_file2 = """\
#!%s
import cgi

print "Content-type: text/html"
print

form = cgi.FieldStorage()
print "%%s, %%s, %%s" %% (form.getfirst("spam"), form.getfirst("eggs"),\
              form.getfirst("bacon"))
"""

class PythonCGITest(testlib.TestlibCase):
    '''Stolen from python2.6 test_httpservers.py'''

    class request_handler(NoLogRequestHandler, CGIHTTPRequestHandler):
        pass

    def setUp(self):
        self.lock = threading.Lock()
        self.thread = TestServerThread(self, self.request_handler)
        self.thread.start()
        self.lock.acquire()

        self.parent_dir = tempfile.mkdtemp()
        self.cgi_dir = os.path.join(self.parent_dir, 'cgi-bin')
        os.mkdir(self.cgi_dir)

        self.file1_path = os.path.join(self.cgi_dir, 'file1.py')
        file1 = open(self.file1_path, 'w')
        file1.write(cgi_file1 % sys.executable)
        os.chmod(self.file1_path, 0777)

        self.file2_path = os.path.join(self.cgi_dir, 'file2.py')
        file2 = open(self.file2_path, 'w')
        file2.write(cgi_file2 % sys.executable)
        os.chmod(self.file2_path, 0777)

        self.cwd = os.getcwd()
        os.chdir(self.parent_dir)

    def tearDown(self):
        try:
            os.chdir(self.cwd)
            os.remove(self.file1_path)
            os.remove(self.file2_path)
            os.rmdir(self.cgi_dir)
            os.rmdir(self.parent_dir)
        finally:
            self.lock.release()
            self.thread.stop()

    def request(self, uri, method='GET', body=None, headers={}):
        self.connection = httplib.HTTPConnection('127.0.0.1', self.PORT)
        self.connection.request(method, uri, body, headers)
        return self.connection.getresponse()

    def test_headers_and_content(self):
        '''Test headers and content'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        res = self.request('/cgi-bin/file1.py')
        self.assertEquals(('Hello World\n', 'text/html', 200), \
             (res.read(), res.getheader('Content-type'), res.status))

    def test_post(self):
        '''Test post'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        import urllib
        params = urllib.urlencode({'spam' : 1, 'eggs' : 'python', 'bacon' : 123456})
        headers = {'Content-type' : 'application/x-www-form-urlencoded'}
        res = self.request('/cgi-bin/file2.py', 'POST', params, headers)

        self.assertEquals(res.read(), '1, python, 123456\n')

    def test_invaliduri(self):
        '''Test invalid uri'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        res = self.request('/cgi-bin/invalid')
        res.read()
        self.assertEquals(res.status, 404)

    def test_authorization(self):
        '''Test authorization'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        import base64
        headers = {'Authorization' : 'Basic %s' % \
                base64.b64encode('username:pass')}
        res = self.request('/cgi-bin/file1.py', 'GET', headers=headers)
        self.assertEquals(('Hello World\n', 'text/html', 200), \
             (res.read(), res.getheader('Content-type'), res.status))

    def test_verify_CVE_2011_1015a(self):
        '''Verify CVE-2011-1015a'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        test_vectors = {
            '': ('/', ''),
            '..': IndexError,
            '/.//..': IndexError,
            '/': ('/', ''),
            '//': ('/', ''),
            '/\\': ('/', '\\'),
            '/.//': ('/', ''),
            'cgi-bin/file1.py': ('/cgi-bin', 'file1.py'),
            '/cgi-bin/file1.py': ('/cgi-bin', 'file1.py'),
            'a': ('/', 'a'),
            '/a': ('/', 'a'),
            '//a': ('/', 'a'),
            './a': ('/', 'a'),
            './C:/': ('/C:', ''),
            '/a/b': ('/a', 'b'),
            '/a/b/': ('/a/b', ''),
            '/a/b/c/..': ('/a/b', ''),
            '/a/b/c/../d': ('/a/b', 'd'),
            '/a/b/c/../d/e/../f': ('/a/b/d', 'f'),
            '/a/b/c/../d/e/../../f': ('/a/b', 'f'),
            '/a/b/c/../d/e/.././././..//f': ('/a/b', 'f'),
            '../a/b/c/../d/e/.././././..//f': IndexError,
            '/a/b/c/../d/e/../../../f': ('/a', 'f'),
            '/a/b/c/../d/e/../../../../f': ('/', 'f'),
            '/a/b/c/../d/e/../../../../../f': IndexError,
            '/a/b/c/../d/e/../../../../f/..': ('/', ''),
        }
        for path, expected in test_vectors.iteritems():
            if isinstance(expected, type) and issubclass(expected, Exception):
                self.assertRaises(expected,
                                  CGIHTTPServer._url_collapse_path_split, path)
            else:
                actual = CGIHTTPServer._url_collapse_path_split(path)
                self.assertEquals(expected, actual,
                                  msg='path = %r\nGot:    %r\nWanted: %r' % (
                                  path, actual, expected))

    def test_verify_CVE_2011_1015b(self):
        '''Verify CVE-2011-1015b'''
        if "python2.5" not in exe and "python2.4" not in exe:
            return self._skipped("included in testsuite")

        res = self.request('cgi-bin/file1.py')
        self.assertEquals(('Hello World\n', 'text/html', 200),
             (res.read(), res.getheader('Content-type'), res.status))


if __name__ == '__main__':
    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        print >>sys.stderr, "Please specify the name of the binary to test (eg 'python2.7 or 'python3.2')"
        print >>sys.stderr, "Eg:"
        print >>sys.stderr, "  %s python2.7"
        print >>sys.stderr, "  %s python3.2 [http://proxy:port]"
        sys.exit(1)

    exe = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] != '-v':
        proxy = sys.argv[2]

    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PythonTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PythonCGITest))
    if use_private:
         # hack to get the global variable in the PythonPrivateTests module
        __builtin__.exe = exe
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PythonPrivateTests))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
