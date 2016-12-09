#!/usr/bin/python
#
#    test-ruby.py quality assurance test script
#    Copyright (C) 2008-2014 Canonical Ltd.
#    Author: Kees Cook <kees@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
#            Marc Deslauriers <marc.deslauriers@canonical.com>
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
      ruby1.8:
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release dovecot-imapd dovecot-pop3d netbase openssl ruby1.8 libopenssl-ruby1.8 openbsd-inetd libwww-perl && ./test-ruby.py ruby1.8 -v'

      ruby1.9:
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release dovecot-imapd dovecot-pop3d netbase openssl ruby1.9 libopenssl-ruby1.9 openbsd-inetd libwww-perl && ./test-ruby.py ruby1.9 -v'

    TODO:
      https with ruby1.9

    NOTE:
      Look at the tcpdump for CVE-2008-3905 carefully-- it's every other
      outgoing packet that has a predictable source port

    NOTE:
      The following tests have been disabled for DoS reasons:
      - test_verify_17530
      - test_CVE_2008_3905
      - test_CVE_2008_3656
      - test_CVE_2008_3443

    NOTE:
      This test script assumes the snakeoil certs were generated with the
      correct hostname. In certain environments, this may not be the case.
      You can regenerate the snakeoil certs by doing the following command
      and rebooting (tests will fail without a reboot):
      $ sudo make-ssl-cert generate-default-snakeoil --force-overwrite

'''

# QRT-Depends: testlib_dovecot.py private/qrt/ruby.py
# QRT-Packages: dovecot-imapd dovecot-pop3d openssl ruby1.8 openbsd-inetd libwww-perl
# QRT-Alternates: ruby1.9 ruby1.9.1
# QRT-Alternates: libopenssl-ruby1.9 libopenssl-ruby1.8
# QRT-Alternates: libhttpclient-ruby1.9 libhttpclient-ruby1.8
# QRT-Privilege: root

import unittest, subprocess, tempfile, os, socket, string, sys, glob
import testlib, testlib_dovecot
import time
import __builtin__

exe = ""
orig_symlinks = []

use_private = True
try:
    from private.qrt.ruby import RubyPrivateTests
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"


class RubyIMAPTest(testlib.TestlibCase):
    '''Test ruby IMAP implementation.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        # Dovecot in quantal+ doesn't like mixed-case usernames
        self.user = testlib.TestUser(lower=True)
        self.dovecot = testlib_dovecot.Dovecot(self,self.user)
        self.rubyscript = tempfile.NamedTemporaryFile(suffix='.rb',prefix='imap-test-')
        os.chmod(self.rubyscript.name,0700)
        self.hostname = self.yank_commonname_from_cert(self.dovecot.get_cert())
        self._remove_snakeoil_symlinks()

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.dovecot = None
        self.user = None
        self.rubyscript = None
        self._restore_snakeoil_symlinks()

    def _remove_snakeoil_symlinks(self):
        '''Remove symlinks to snakeoil cert'''
        snakeoil = '/etc/ssl/certs/ssl-cert-snakeoil.pem'

        for root, dirs, files in os.walk('/etc/ssl/certs'):
            for name in files:
                fqname = os.path.join(root, name)
                if os.path.islink(fqname):
                    if os.path.join(os.path.dirname(snakeoil), os.readlink(fqname)) == snakeoil:
                        orig_symlinks.append(fqname)
                        os.rename(fqname, '%s.tempo' % fqname)

    def _restore_snakeoil_symlinks(self):
        '''Restore symlinks to snakeoil cert'''
        while (orig_symlinks):
            symlink = orig_symlinks.pop()
            os.rename('%s.tempo' % symlink, symlink)

    def _prep_imap_script(self,sslcert=None,sslport=993,host=None):

        if not host:
            host = self.hostname
        sslstr='false'
        port='143'
        if sslcert:
            sslstr='true'
            port=sslport
        self.rubyscript.write('''#!/usr/bin/%s
# http://wonko.com/post/554
require 'net/imap'

# Source server connection info.
SOURCE_HOST = '%s'
SOURCE_PORT = %s
SOURCE_SSL  = %s
SOURCE_USER = '%s'
SOURCE_PASS = '%s'

def ds(message)
   puts "[#{SOURCE_HOST}] #{message}"
end

# Connect and log into both servers.
ds 'connecting...'
if SOURCE_SSL
    certs = '%s'
    source = Net::IMAP.new(SOURCE_HOST, SOURCE_PORT, SOURCE_SSL, certs, true)
else
    source = Net::IMAP.new(SOURCE_HOST, SOURCE_PORT)
end

ds 'logging in...'
source.login(SOURCE_USER, SOURCE_PASS)

source_folder = 'INBOX'
begin
    ds "selecting folder '#{source_folder}'..."
    source.examine(source_folder)
rescue => e
    ds "error: select failed: #{e}"
end

uids = source.uid_search(['ALL'])
ds "saw '#{uids}'"

source.close
''' % (exe,host,port,sslstr,self.user.login,self.user.password,sslcert))
        self.rubyscript.flush()

    def test_imap(self):
        '''Test IMAP4 module'''
        self._prep_imap_script(host='localhost')
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertEqual(rc,0,out)
        if exe == "ruby1.8":
            self.assertTrue("[localhost] saw '1" in out,out)
        else:
            self.assertTrue("[localhost] saw '[1" in out,out)

    def test_imaps(self):
        '''Test IMAP4 module with SSL'''
        self._prep_imap_script(sslcert=self.dovecot.get_cert())
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertEqual(rc,0,out)
        if exe == "ruby1.8":
            self.assertTrue("[%s] saw '1"%(self.hostname) in out,out)
        else:
            self.assertTrue("[%s] saw '[1"%(self.hostname) in out,out)

    def test_imaps_bad_cert(self):
        '''Test IMAP4 module with SSL (bad cert)'''
        self._prep_imap_script(sslcert='/dev/null')
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertNotEqual(rc,0,out)

    def test_imaps_bad_cname(self):
        '''Test IMAP4 module with SSL (bad commonName) CVE-2007-5770'''
        # Use "127.0.0.1" to break commonName check
        self._prep_imap_script(sslcert=self.dovecot.get_cert(),host='127.0.0.1')
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertNotEqual(rc,0,out)


class HTTPSTest(testlib.TestlibCase):
    '''Test HTTPS implementations.'''

    def _setUp(self):
        '''Set up prior to each test_* function'''
        self.rubyscript = tempfile.NamedTemporaryFile(suffix='.rb',prefix='https-test-')
        os.chmod(self.rubyscript.name,0700)
        self.cert = '/etc/ssl/certs/ssl-cert-snakeoil.pem'
        self.sslserver = subprocess.Popen(['openssl','s_server','-accept','9993','-cert',self.cert,'-key','/etc/ssl/private/ssl-cert-snakeoil.key','-www'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        self.hostname = self.yank_commonname_from_cert(self.cert)
        if self.hostname not in [socket.gethostname(), socket.gethostname() + ".defaultdomain"]:
            print "\n\nWARNING: snakeoil cert doesn't match hostname! See test script header!\n"

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self.rubyscript = None
        os.kill(self.sslserver.pid,9)

    @unittest.skip("FIXME: This test no longer works!")
    def test_http(self):
        '''Test HTTP'''

        self._prep_http_script(verify=False,host='www.ubuntu.com')
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertEqual(rc,0,out)
        self.assertTrue('<html' in out.lower(),out)

    def test_https(self):
        '''Test HTTPS without SSL verifications'''
        if not exe.startswith("ruby1.8"):
            return self._skipped(exe + " not supported")

        self._prep_http_script(ssl=True,verify=False,port=9993)
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertEqual(rc,0,out)
        self.assertTrue('Ciphers supported in s_server binary' in out,out)

    def test_https_good(self):
        '''Test HTTPS checks for valid cert'''
        self._prep_http_script(verify=True,host=self.hostname,port=9993)
        rc, out = testlib.cmd([exe,self.rubyscript.name])

        self.assertEqual(rc,0,out)
        self.assertTrue('Ciphers supported in s_server binary' in out,out)

    def test_https_leak(self):
        '''Test Auth Details are not leaked via HTTPS (CVE-2007-5162)'''
        # Use "127.0.0.1" to break commonName check
        self._prep_http_script(verify=True,host='127.0.0.1',port=9993)
        rc, out = testlib.cmd([exe,self.rubyscript.name])
        self.assertNotEqual(rc,0,out)

class RubyHTTPSTest(HTTPSTest):
    '''Test Ruby HTTPS implementation.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self._setUp()

    def _tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()

    def _prep_http_script(self,ssl=False,verify=True,host=None,port=80):
        verifystr = ""
        if verify:
            ssl = True
            suffix = "s"
            verifystr += "http.verify_mode = OpenSSL::SSL::VERIFY_PEER\n"
            verifystr += "http.ca_file = '/etc/ssl/certs/ssl-cert-snakeoil.pem'\n"
        suffix = ""
        if ssl:
            suffix = "s"
            verifystr += "http.use_ssl = true\n"
        if not host:
            host = self.hostname
        self.rubyscript.write('''#!/usr/bin/%s
require 'net/http%s'
require 'open-uri'
#require 'net/telnets'
#require 'net/ftptls'
http = Net::HTTP.new('%s', %d)
%s
http.start do |http|
    request = Net::HTTP::Get.new('/')
    response = http.request(request)
    response.value
    puts response.body
end
''' % (exe,suffix,host,port,verifystr))
        self.rubyscript.flush()

class RubygemsHTTPSTest(HTTPSTest):
    '''Test Rubygems fetcher HTTPS implementation.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.gemrc_path = os.path.join(os.path.expanduser('~'), '.gemrc')

        self._setUp()
        testlib.config_replace(self.gemrc_path, '')

    def tearDown(self):
        '''Clean up after each test_* function'''
        self._tearDown()
        testlib.config_restore(self.gemrc_path)

    def _prep_http_script(self,ssl=False,verify=True,host=None,port=80):
        gemrc = ""
        protocol = "http"

        if ssl or verify:
            rc, out = testlib.cmd([exe, '-r', 'rubygems', '-e',
                                   'if !defined?(Gem.configuration.ssl_verify_mode) then exit 1 end'])
            self.assertEquals(rc, 0, exe + ' does not have SSL support in the rubygems fetcher')

        if verify:
            ssl = True
            rc, out = testlib.cmd([exe, '-r', 'openssl', '-e', 'puts OpenSSL::SSL::VERIFY_PEER'])
            gemrc += ":ssl_verify_mode: %s\n" % out
            gemrc += ":ssl_ca_cert: /etc/ssl/certs/ssl-cert-snakeoil.pem\n"
        else:
            rc, out = testlib.cmd([exe, '-r', 'openssl', '-e', 'puts OpenSSL::SSL::VERIFY_NONE'])
            gemrc += ":ssl_verify_mode: %s\n" % out

        gemrc_file = open(self.gemrc_path, "w")
        gemrc_file.write(gemrc)
        gemrc_file.close()

        if ssl:
            protocol += "s"

        if not host:
            host = self.hostname

        self.rubyscript.write('''#!/usr/bin/%s
require 'rubygems/remote_fetcher'

puts Gem::RemoteFetcher.new.fetch_path('%s://%s:%d')
''' % (exe, protocol, host, port))
        self.rubyscript.flush()

class RubygemsTest(testlib.TestlibCase):
    '''Test rubygems functionality.'''

    def setUp(self):
        self.tmpdir = ""
        self.gemrc_path = os.path.join(os.path.expanduser('~'), '.gemrc')

        rc, out = testlib.cmd([exe, '-r', 'openssl', '-e', 'puts OpenSSL::SSL::VERIFY_PEER'])
        # Make sure that cert verification is done, but don't specify
        # ssl_ca_cert to make sure that a default rubygems installation uses
        # /etc/ssl/certs/ca-certificates.crt
        testlib.config_replace(self.gemrc_path, ":ssl_verify_mode: %s\n" % out)

    def tearDown(self):
        testlib.config_restore(self.gemrc_path)

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_gem_fetch(self):
        ''' Test fetching the 5 most popular gems from https://rubygems.org '''
        gems = [ 'rake', 'mime-types', 'multi_json', 'rack', 'tilt' ]
        failed = ''

        cwd = os.getcwd()
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        os.chdir(self.tmpdir)
        for gem in gems:
            rc, out = testlib.cmd(['gem', 'fetch', gem])
            gem = glob.glob(os.path.join(self.tmpdir, gem + '*.gem'))
            if rc != 0 or not gem:
                failed += gem + ' '

        os.chdir(cwd)
        self.assertEqual(failed, '', 'gem fetch failed for ' + failed)

    def test_gem_install(self):
        ''' Test installing the 5 most popular gems from https://rubygems.org '''
        gems = [ 'rake', 'mime-types', 'multi_json', 'rack', 'tilt' ]
        failed = ''

        for gem in gems:
            ''' Skip installed gems to make cleanup/uninstallation easier '''
            rc, out = testlib.cmd(['gem', 'list', '-i', gem])  
            if rc == 0:
                continue

            ''' Ignore dependencies to make cleanup/uninstallation easier '''
            rc, out = testlib.cmd(['gem', 'install', '--ignore-dependencies', gem])
            if rc != 0:
                failed += gem + ' '
                continue

            rc, out = testlib.cmd(['gem', 'list', '-i', gem])  
            if rc != 0:
                failed += gem + ' '
                continue

            testlib.cmd(['gem', 'uninstall', '-Ix', gem])

        self.assertEqual(failed, '', 'gem install failed for ' + failed)

    def test_gem_search(self):
        gem = 'rake'
        rc, out = testlib.cmd(['gem', 'search', '-r', gem])  
        self.assertEqual(rc, 0, 'gem search failed for ' + gem)
        self.assertTrue(gem in out, 'gem search did not find ' + gem)

class RubyPatchRegressionTest(testlib.TestlibCase):
    '''Test ruby patch regressions.'''
    def setUp(self):
        self.tmpdir = ""
        '''Set up prior to each test_* function'''
        self.rubyscript = tempfile.NamedTemporaryFile(suffix='.rb',prefix='patch-test-')
        os.chmod(self.rubyscript.name,0700)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.rubyscript = None

        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _test_verify_17530(self):
        '''Verify r17530 is applied (takes a long time)'''
        test_str = '''str = "A"*(2**16) ; loop{ str << str ; puts str.size }'''
        rc, out = testlib.cmd([exe, '-ve', test_str])
        if 'string sizes too big' not in out and \
           'failed to allocate memory' not in out:
            self.assertEqual(True,False,out)

    def test_verify_CVE_2008_3655_untrace(self):
        '''Verify CVE-2008-3655 (untrace)'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
trace_var(:$VAR) {|val| puts "$VAR = #{val}" }

Thread.new do
 $SAFE = 4
 eval %%q{
   proc = untrace_var :$VAR
   proc.first.call("aaa")
 }
end.join
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "SecurityError"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2008_3655_program_name(self):
        '''Verify CVE-2008-3655 ($PROGRAM_NAME)'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
Thread.new do
 $SAFE = 4
 eval %%q{$PROGRAM_NAME.replace "Hello, World!"}
end.join
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "TypeError"
        if exe.startswith("ruby1.9"):
            str = "can't modify frozen String"
        elif exe.startswith("ruby2.0"):
            str = "Insecure: can't modify string"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2008_3655_insecure_methods(self):
        '''Verify CVE-2008-3655 (insecure methods)'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
class Hello
 def world
   Thread.new do
     $SAFE = 4
     msg = "Hello, World!"
     def msg.size
       self.replace self*10 # replace string
       1 # return wrong size
     end
     msg
   end.value
 end
end

$SAFE = 1 # or 2, or 3
s = Hello.new.world
if s.kind_of?(String)
 puts s if s.size < 20 # print string which size is less than 20
end
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "SecurityError"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2008_3655_syslog(self):
        '''Verify CVE-2008-3655 (syslog)'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
require "syslog"

Syslog.open

Thread.new do
 $SAFE = 4
 eval %%q{
   Syslog.log(Syslog::LOG_WARNING, "Hello, World!")
   Syslog.mask = Syslog::LOG_UPTO(Syslog::LOG_EMERG)
   Syslog.info("masked")
   Syslog.close
 }
end.join
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "SecurityError"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2008_3657(self):
        '''Verify CVE-2008-3657'''
        if not exe.startswith("ruby1.8"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
require 'dl'
$SAFE = 1
h = DL.dlopen(nil)
sys = h.sym('system', 'IP')
uname = 'uname -rs'.taint
sys[uname]
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "SecurityError"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2013_2065_1(self):
        '''Verify CVE-2013-2065 (Part 1)'''

        if exe.startswith("ruby1.8"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
require 'dl'
require 'dl/func'
def my_function(user_input)
  handle    = DL.dlopen(nil)
  sys_cfunc = DL::CFunc.new(handle['system'], DL::TYPE_INT, 'system')
  sys       = DL::Function.new(sys_cfunc, [DL::TYPE_VOIDP])
  sys.call user_input
end

$SAFE = 1
my_function "uname -rs".taint
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "SecurityError"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2013_2065_2(self):
        '''Verify CVE-2013-2065 (Part 2)'''

        if exe.startswith("ruby1.8"):
            return self._skipped(exe + " not supported")

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
require 'dl'
def my_function(user_input)
  handle    = DL.dlopen(nil)
  sys = Fiddle::Function.new(handle['system'],
                             [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)
  sys.call user_input
end

$SAFE = 1
my_function "uname -rs".taint
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)
        str = "SecurityError"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2008_3790(self):
        '''Verify CVE-2008-3790 (DoS)'''
        self.rubyscript.write('''#!/usr/bin/%s
require 'rexml/document'

doc = REXML::Document.new(<<END)
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE member [
  <!ENTITY a "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
  <!ENTITY b "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;">
  <!ENTITY c "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;">
  <!ENTITY d "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">
  <!ENTITY e "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;">
  <!ENTITY f "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">
  <!ENTITY g "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx">
]>
<member>
&a;
</member>
END

puts doc.root.text.size
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)

        errorA = "number of entity expansions exceeded"
        errorB = "entity expansion has grown too large"
        warning = 'Could not find error message in output!\n'
        self.assertTrue((errorA in out) or (errorB in out), warning + out)

    def test_verify_CVE_2014_8080(self):
        '''Verify CVE-2014-8080 (DoS)'''
        self.rubyscript.write('''#!/usr/bin/''' + exe + '''
require 'rexml/document'
REXML::Document.entity_expansion_limit = 100
doc = REXML::Document.new(<<END)
<!DOCTYPE root [
  <!ENTITY % a "BOOM.BOOM.BOOM.BOOM.BOOM.BOOM.BOOM.BOOM.BOOM.">
  <!ENTITY % b "%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;">
  <!ENTITY % c "%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;">
  <!ENTITY % d "%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;">
  <!ENTITY % e "%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;">
  <!ENTITY % f "%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;">
  <!ENTITY % g "%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;">
  <!ENTITY test "test %g;">
]>
<cd></cd>
END

puts doc.root.text.size
''')
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)

        errorA = "number of entity expansions exceeded"
        errorB = "entity expansion has grown too large"
        warning = 'Could not find error message in output!\n'
        self.assertTrue((errorA in out) or (errorB in out), warning + out)

    def test_verify_CVE_2014_8090(self):
        '''Verify CVE-2014-8090 (DoS)'''
        self.rubyscript.write('''#!/usr/bin/''' + exe + '''
require 'rexml/document'
REXML::Document.entity_expansion_limit = 100
doc = REXML::Document.new(<<END)
<!DOCTYPE root [
  <!ENTITY % a "">
  <!ENTITY % b "%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;">
  <!ENTITY % c "%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;">
  <!ENTITY % d "%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;">
  <!ENTITY % e "%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;">
  <!ENTITY % f "%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;">
  <!ENTITY % g "%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;">
  <!ENTITY test "test %g;">
]>
<cd></cd>
END

puts doc.root.text.size
''')
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(rc, 0, out)

        errorA = "number of entity expansions exceeded"
        errorB = "entity expansion has grown too large"
        warning = 'Could not find error message in output!\n'
        self.assertTrue((errorA in out) or (errorB in out), warning + out)

    def _test_CVE_2008_3905(self):
        '''Verify CVE-2008-3905 (name resolver)'''
        print >>sys.stdout, "\n  'run sudo tcpdump -i eth0 -s1500 -n udp port 53' on this host"
        print >>sys.stdout, "  waiting 10 seconds"
        sys.stdout.flush()
        time.sleep(10)

        self.rubyscript.write('''#!/usr/bin/%s
require 'resolv'
res=Resolv::DNS.new;
10.times do result = res.getaddress("www.ruby-lang.org")
p Time.now()
p result
end
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        str = "#<Resolv::IPv4 221.186.184.68>"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2009_1904_1(self):
        '''Verify CVE-2009-1904 (PoC)'''
        self.rubyscript.write('''#!/usr/bin/%s
require 'bigdecimal'
res = BigDecimal("1"*10000000)
res2 = BigDecimal("9E69999999").to_s("F")
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + out)

    def test_verify_CVE_2014_4975(self):
        '''Verify CVE-2014-4975 (PoC)'''
        self.rubyscript.write('''#!/usr/bin/%s
size = ((4096-4)/4*3+1)
new_size = ["a"*size].pack("m#{size+2}").unpack("m")[0].size
if size == new_size
  exit 0
else
  exit 1
end
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + out)

    def test_verify_CVE_2009_1904_2(self):
        '''Verify CVE-2009-1904 (regression)'''
        self.rubyscript.write('''#!/usr/bin/%s
require 'bigdecimal'
res = Float(BigDecimal("49.06"))
print (res)
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + out)

        str = "49.06"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

    def test_verify_CVE_2011_0188(self):
        '''Verify CVE-2011-0188'''
        if self.dpkg_arch != 'amd64':
            return self._skipped("arch '%s' is not not affected" % testlib.get_arch())

        self.rubyscript.write('''#!/usr/bin/%s
require 'bigdecimal'
res = BigDecimal.new("8").**(0x20000000)
print res
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        str = 'Segmentation fault'
        self.assertFalse(str in out, out)

    def test_verify_exc_to_s_fix_1(self):
        '''Verify CVE-2011-1005 (1.8.x), CVE-2012-4464 (>= 1.9.3)'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
s = "foo"
t = Thread.new do
    $SAFE = 4
    Exception.new(s).to_s
    begin
        s.replace "bar"
        1
    rescue SecurityError
        0
    end
end
t.join
print s
exit t.value
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

        expected = 'foo'
        result = 'Got output [%s], expected [%s]\n' % (out, expected)
        self.assertEqual(out, expected, result)

    def test_verify_exc_to_s_fix_2(self):
        '''Verify CVE-2012-4481'''
        self.rubyscript.write('''#!/usr/bin/%s
m = "foo"
e = Exception.new(m)
e.taint
s = e.to_s
if m.tainted? == false && s.tainted? == false
    exit 0
end
exit 1
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

    def test_verify_name_err_to_s_fix_1(self):
        '''Verify CVE-2011-1005 (1.8.x), CVE-2012-4464 (>= 1.9.3)'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
s = "foo"
t = Thread.new do
    $SAFE = 4
    NameError.new(s).to_s
    begin
        s.replace "bar"
        1
    rescue SecurityError
        0
    end
end
t.join
print s
exit t.value
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

        expected = 'foo'
        result = 'Got output [%s], expected [%s]\n' % (out, expected)
        self.assertEqual(out, expected, result)

    def test_verify_name_err_to_s_fix_2(self):
        '''Verify CVE-2011-1005 (1.8.x), CVE-2012-4464 (>= 1.9.3)'''
        self.rubyscript.write('''#!/usr/bin/%s
m = "foo"
e = NameError.new(m)
e.taint
s = e.to_s
if m.tainted? == false && s.tainted? == false
    exit 0
end
exit 1
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

    def test_verify_name_err_mesg_to_s_fix_1(self):
        '''Verify CVE-2012-4466'''

        if exe.startswith("ruby2.1"):
            return self._skipped(exe + " not supported")

        self.rubyscript.write('''#!/usr/bin/%s
s = "foo"
t = Thread.new do
    $SAFE = 4
    o = Object.new
    class << o; self; end.instance_eval { define_method(:to_str) { s } }
    NameError.new(o).to_s
    begin
        s.replace("bar")
        1
    rescue SecurityError
        0
    end 
end
t.join
print s
exit t.value
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

        expected = 'foo'
        result = 'Got output [%s], expected [%s]\n' % (out, expected)
        self.assertEqual(out, expected, result)

    def test_verify_name_err_mesg_to_s_fix_2(self):
        '''Verify CVE-2012-4481'''
        self.rubyscript.write('''#!/usr/bin/%s
o = Object.new
def o.to_str
    "foo"
end
o.taint
e = NameError.new(o)
s = e.to_s
if s.tainted? == false
    exit 0
end
exit 1
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

    def test_verify_CVE_2011_2686(self):
        '''Verify CVE-2011-2686'''
        self.rubyscript.write('''#!/usr/bin/%s
fork { $stdout.syswrite("#{rand}\n") }
$stdout.syswrite("#{rand}\n")
Process.waitall
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

        rand_val = string.split(out)
        expected = 2
        result = 'Expected %d random values to be output\n' % expected
        self.assertEqual(len(rand_val), expected, result + out)

        result = 'PRNG not reseeded after forking\n'
        self.assertNotEqual(rand_val[0], rand_val[1], result + out)

    def test_verify_CVE_2011_2705(self):
        '''Verify CVE-2011-2705'''
        self.rubyscript.write('''#!/usr/bin/%s
require 'securerandom'
require 'openssl'

SecureRandom.hex()
orig_pid = fork { print SecureRandom.hex(), "\n" }
Process.wait

last_pid = orig_pid
while true
    pid = fork { print SecureRandom.hex(), "\n" if $$ == orig_pid }
    Process.wait

    if pid == orig_pid
        exit 0
    elsif (last_pid < orig_pid && pid > orig_pid) ||
          (last_pid > orig_pid && pid > orig_pid && pid < last_pid)
        # basic protection from an infinite loop if pid skips over orig_pid
        exit 1
    end
    last_pid = pid
end
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        if rc == 1:
            # Couldn't hit the same PID number through PID wrap around. Give it
            # one more shot and then skip the test if we fail again.
            rc, out = testlib.cmd([exe, self.rubyscript.name])
            if rc == 1:
                return self._skipped("Test must run under the same PID twice. This was not possible; please try again.\n")
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out)

        rand_hex = string.split(out)
        expected = 2
        result = 'Expected %d random hashes to be output\n' % expected
        self.assertEqual(len(rand_hex), expected, result + out)

        result = 'OpenSSL seed only based on PID number\n'
        self.assertNotEqual(rand_hex[0], rand_hex[1], result + out)

    def test_verify_CVE_2011_4815(self):
        '''Verify CVE-2011-4815'''
        self.rubyscript.write('''#!/usr/bin/%s
foo = 'foo'
print foo.hash.to_s, "\n"
''' % (exe))
        self.rubyscript.flush()

        rc, out1 = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEqual(expected, rc, result + out1)

        rc, out2 = testlib.cmd([exe, self.rubyscript.name])
        self.assertEqual(expected, rc, result + out2)

        result = 'Hash output not randomized\n'
        self.assertNotEqual(out1, out2, result + out1 + out2)

    def test_verify_CVE_2012_4522(self):
        '''Verify CVE-2012-4522'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        should_not_exist = os.path.join(self.tmpdir, 'foo')
        self.rubyscript.write('''#!/usr/bin/%s
open("%s\0bar", "w")
exit File.exists?("%s")
''' % (exe, should_not_exist, should_not_exist))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        self.assertNotEqual(0, rc)
        self.assertTrue('ArgumentError' in out)
        self.assertFalse(os.path.exists(should_not_exist))

    def test_verify_CVE_2013_4164(self):
        '''Verify CVE-2013-4164'''
        self.rubyscript.write('''#!/usr/bin/%s
res = ("1."+"1"*300000).to_f*9
print (res)
''' % (exe))
        self.rubyscript.flush()

        rc, out = testlib.cmd([exe, self.rubyscript.name])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + out)

        str = "10.0"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)


class RubyPatchRegressionWEBrickTest(testlib.TestlibCase):
    '''Test ruby patch regressions.'''
    def setUp(self):
        '''Set up prior to each test_* function'''
        self.rubyscript = tempfile.NamedTemporaryFile(suffix='.rb',prefix='patch-test-')
        os.chmod(self.rubyscript.name,0700)

        self.wblog = tempfile.NamedTemporaryFile(suffix='.log',prefix='patch-test-')
        os.chmod(self.wblog.name,0700)

        self.wbscript = tempfile.NamedTemporaryFile(suffix='.rb',prefix='patch-test-')
        os.chmod(self.wbscript.name,0700)
        self.wbscript.write('''#!/usr/bin/%s
require 'webrick'
WEBrick::HTTPServer.new(:Port => 2000, :DocumentRoot => '/etc').start
''' % (exe))
        self.wbscript.flush()
        self.wbserver = subprocess.Popen([exe, self.wbscript.name],stdout=self.wblog.fileno(),stderr=subprocess.STDOUT)

    def tearDown(self):
        '''Clean up after each test_* function'''
        self.rubyscript = None
        self.wbscript = None
        self.wblog = None
        os.kill(self.wbserver.pid, 9)

    def _check_log(self, str):
        '''Make sure the server is up and running'''
        try:
            fh = open(self.wblog.name, 'r')
        except:
            raise

        lines = fh.readlines()
        fh.close()
        for line in lines:
            if str in line:
                return True

        return False

    def _test_CVE_2008_3656(self):
        '''Verify CVE-2008-3656 (DoS: CPU resource consumption)'''
        print >>sys.stdout, "\n  waiting 10 seconds..."
        sys.stdout.flush()
        time.sleep(10)

        msg = "TCPServer Error"
        self.assertTrue(not self._check_log(msg), "Found '" + msg + "' (is a stray ruby process still running?)")

        # give child a chance to setup
        print >>sys.stdout, "  pid is %s" % (self.wbserver.pid)

        self.rubyscript.write('''#!/usr/bin/%s
require 'net/http'
res = Net::HTTP.start("localhost", 2000) { |http|
  req = Net::HTTP::Get.new("/passwd")
  req['If-None-Match'] = %%q{meh=""} + %%q{foo="bar" } * 100
  http.request(req)
}
p res
''' % (exe))
        self.rubyscript.flush()
        rc, out = testlib.cmd([exe, self.rubyscript.name])
        str = "200 OK"
        warning = 'Could not find "%s"\n' % str
        self.assertTrue(str in out, warning + out)

        cmdline = "/proc/%d/cmdline" % (self.wbserver.pid)
        self.assertTrue(os.path.exists(cmdline))

    def _test_CVE_2008_3443(self):
        '''Verify CVE-2008-3443 (DoS: memory exhaustion (takes a long time))'''
        print >>sys.stdout, "\n  waiting 10 seconds..."
        sys.stdout.flush()
        time.sleep(10)

        msg = "TCPServer Error"
        self.assertTrue(not self._check_log(msg), "Found '" + msg + "' (is a stray ruby process still running?)")

        # give child a chance to setup
        print >>sys.stdout, "  pid is %s" % (self.wbserver.pid)

        rc, out = testlib.cmd(['perl', '-e', 'use LWP::Simple; my $payload = "\x41" x 49999999; get "http://127.0.0.1:2000/".$payload."";'])
        self.assertEqual(rc, 0, out)
        msg = "NoMemoryError"
        self.assertTrue(not self._check_log(msg), "Found " + msg)

        cmdline = "/proc/%d/cmdline" % (self.wbserver.pid)
        self.assertTrue(os.path.exists(cmdline))


if __name__ == '__main__':
    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        print >>sys.stderr, "Please specify the name of the binary to test (eg 'ruby1.8', 'ruby1.9', or 'ruby1.9.1')"
        sys.exit(1)

    exe = sys.argv[1]

    suite = unittest.TestSuite()

    if exe == "rubygems":
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubygemsHTTPSTest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubygemsTest))
        exe = "ruby"
        use_private = False
    else:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubyHTTPSTest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubyIMAPTest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubyPatchRegressionTest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubyPatchRegressionWEBrickTest))

    if exe.startswith("ruby1.9"):
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubygemsHTTPSTest))
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubygemsTest))

    if use_private:
         # hack to get the global variable in the RubyPrivateTests module
        __builtin__.exe = exe
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(RubyPrivateTests))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
