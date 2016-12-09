#!/usr/bin/python
# coding=utf-8
# (Needed for test_crypt_blowfish_CVE_2011_2483)
#
#    test-php.py quality assurance test script
#    Copyright (C) 2008-2016 Canonical Ltd.
#    Author: Kees Cook <kees@canonical.com>
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#    Author: Steve Beattie <steve.beattie@canonical.com>
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release php5-cli php5-sqlite php5-gd php5-xmlrpc php-pear libapache2-mod-php5 apache2-mpm-prefork elinks php5-tidy php5-curl && ./test-php.py -v'

'''

# QRT-Depends: php testlib_httpd.py private/qrt/php.py data/c0419bt_.pfb data/exif-data.jpg
# QRT-Packages: php5-cli php5-sqlite php5-gd php5-xmlrpc libapache2-mod-php5 apache2-mpm-prefork elinks php-pear php5-cgi php5-tidy php5-curl php5-enchant
# Only required on 13.10 and higher
# QRT-Alternates: php5-json
# QRT-Privilege: root

import unittest, subprocess, shutil, os, os.path, sys
import re
import testlib, tempfile
import testlib_httpd
import __builtin__

# Support testing both php5 and php7.0
app = ''

use_private = True
try:
    from private.qrt.php import PhpPrivateTests
except ImportError:
    use_private = False
    print >>sys.stdout, "Skipping private tests"

class PHPTest(testlib.TestlibCase):
    '''Test php functionality.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="php-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _run_script(self, contents, expected=0, args=[]):
        '''Run a php script, expecting exit code 0'''
        handle, name = testlib.mkstemp_fill('<?php\n'+contents+'\n?>\n')
        self.assertShellExitEquals(expected, ['/usr/bin/'+app] + args, stdin = handle)
        os.unlink(name)

    def _check_script_results(self, contents, results, expected=0, args=[], invert=False):
        '''Run a php script, check if results contain text'''
        handle, name = testlib.mkstemp_fill('<?php\n'+contents+'\n?>\n')
        rc, report = testlib.cmd(['/usr/bin/'+app] + args, stdin = handle)
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        os.unlink(name)

        if invert == False:
            warning = 'Could not find "%s"\n' % results
            self.assertTrue(results in report, warning + report)
        else:
            warning = 'Found "%s"\n' % results
            self.assertFalse(results in report, warning + report)

    def test_a_simple_application(self):
        '''Simple "Hello World" application'''

        self._run_script('echo "Hello World";')

    def test_mopb_10(self):
        '''Protected against MOPB 10'''

        self._run_script('''
  session_start();
  $x = chr(36).str_repeat("A", 36)."N;".chr(127);
  $data = $x;
  
  session_decode($data);
  $keys = array_keys($_SESSION);
  $heapdump = $keys[1];

  exit(strlen($heapdump));
''', args=['-d','session.serialize_handler=php_binary'])

    def test_mopb_14(self):
        '''Protected against MOPB 14'''

        # This fails on Lucid+, need to investigate
        if self.lsb_release['Release'] >= 10.04:
            return self._skipped("TODO: investigate failure on Lucid+")

        self._run_script('''
  $sizeofHashtable = 39;
  $maxlong = 0x7fffffff;
  if (is_int($maxlong+1)) {
    $sizeofHashtable = 67;
    $maxlong = 0x7fffffffffffffff;
  }

  $memdump = str_repeat("A", 4096);
  for ($i=0; $i<40; $i++) $d[] = array();
  unset($d[20]);
  $x = str_repeat("A", $sizeofHashtable);
  
  // If the libc memcmp leaks the information use it
  // otherwise we only get a case insensitive memdump
  $b = substr_compare(chr(65),chr(0),0,1,false) != 65;

  for ($i=0; $i<4096; $i++) {
    $y = substr_compare($x, chr(0), $i+1, $maxlong, $b);
    $Y = substr_compare($x, chr(1), $i+1, $maxlong, $b);
    if ($y-$Y == 1 || $Y-$y==1){
      $y = chr($y);
      if ($b && strtoupper($y)!=$y) {
        if (substr_compare($x, $y, $i+1, $maxlong, false)==-1) {
          $y = strtoupper($y);
        }
      }
      $memdump[$i] = $y;
    } else {
      $memdump[$i] = chr(0);
    }
  }

  $rc = 0;
  for ($b=0; $b<strlen($memdump); $b+=1) {
    if ($memdump[$b] != chr(0)) {
        $rc = 1;
    }
  }
  if ($rc) {
    echo "Saw leaked memory in memdump\n";
  }

  exit($rc);
  
''')

    def test_mopb_15(self):
        '''Protected against MOPB 15'''

        self._run_script('''
  function init()
  {
    global $rid;
    
    $rid = imagecreate(10,10);
    imagecolorallocate($rid, 0, 0, 0);
    imagecolorallocate($rid, 0, 0, 0);
  }
  
  function peek($addr, $size)
  {
    global $rid;
    imagecolordeallocate($rid, 0);
    imagecolordeallocate($rid, 1);
    imagecolorallocate($rid, $addr, 0, 0);
    imagecolorallocate($rid, $size, 0, 0);
    return shmop_read((int)$rid, 0, $size);
  }

  init();

    $maps = fopen("/proc/self/maps","r");
    while (!feof($maps)) {
        $line = fgets($maps, 4096);
        echo $line;
        $sections = explode(' ',$line);
        $addrs = explode('-',$sections[0]);
        $perms = $sections[1];

        $offset = intval($addrs[0],16);
        $size = intval($addrs[1],16) - $offset;

        if ($size && strpos($perms,"r")!==false && strpos($perms,"w")!==false) {
            $span = $size;
            if ($span > 1024) {
                $span = 1024;
            }

            echo "Attempting to read $span from $offset\n";

            $data = peek($offset,$span);
            if (strlen($data) == $span) {
                echo "Oops, able to read memory!\n";
                exit(1);
            }
            echo "Unable to read memory\n";
            exit(0);
        }
    }
''')

    def test_mopb_22(self):
        '''Protected against MOPB 22'''

        self._run_script('''
  $offset_1 = 0x55555555;
  $offset_2 = 0x08048040;
  // Convert offsets into strings
  $addr1 = pack("L", $offset_1);
  $addr2 = pack("L", $offset_2);

  define("C0", $addr1[0]);
  define("C1", $addr1[1]);
  define("C2", $addr1[2]);
  define("C3", $addr1[3]);
  
  define("M0", $addr2[0]);
  define("M1", $addr2[1]);
  define("M2", $addr2[2]);
  define("M3", $addr2[3]);
  
  function myErrorHandler()
  {
    session_id(str_repeat("A", 100));
    
    $GLOBALS['str'] = str_repeat("A", 39);
    
    for ($i=0; $i<7; $i++) {
      $GLOBALS['str'][$i*4+0] = M0;
      $GLOBALS['str'][$i*4+1] = M1;
      $GLOBALS['str'][$i*4+2] = M2;
      $GLOBALS['str'][$i*4+3] = M3;
    }
    $GLOBALS['str'][8*4+0] = C0;
    $GLOBALS['str'][8*4+1] = C1;
    $GLOBALS['str'][8*4+2] = C2;
    $GLOBALS['str'][8*4+3] = C3;

    return true;
  }
  
  function doit()
  {
    error_reporting(E_ALL);
    set_error_handler("myErrorHandler");
    session_id(str_repeat("A", 39));
    session_start();
    session_regenerate_id();
  }
  
  doit();
''',args=['-d','session.hash_bits_per_character=666'])

    def test_mopb_24(self):
        '''Protected against MOPB 24'''

        self._run_script('''
  $shellcode = str_repeat(chr(0x90), 1000);

  $arr = array(str_repeat("A", 39) => 1, "B" => 1);

  function array_compare(&$key1, &$key2)
  {
    $GLOBALS['a'] = &$key2;
    unset($key2);
    return 1;
  }

  uksort($arr, "array_compare");
  $x=array($shellcode => 1);

  $a[8*4+0] = $a[6*4+0];
  $a[8*4+1] = chr(ord($a[6*4+1])+2); // <--- This only works for Little Endian
  $a[8*4+2] = $a[6*4+2];
  $a[8*4+3] = $a[6*4+3];

  unset($x);
''')

    # This needs to use mod_php to test for long-running register_globals
    # behavior.
    def _test_mopb_26(self):
        '''Protected against MOPB 26'''

        self._run_script('''
  $str = "a=".str_repeat("A", 164000);

  // This code just fills the memory up to the limit...
  $limit = ini_get("memory_limit");
  if (strpos($limit, "M")) {
    $limit *= 1024 * 1024;
  } else if (strpos($limit, "K")) {
    $limit *= 1024;
  } else $limit *=1;
  while ($limit - memory_get_usage(true) > 2048) $x[] = str_repeat("A", 1024);

  // Will activate register_globals and trigger the memory_limit
  mb_parse_str($str);
''')

    def test_mopb_29(self):
        '''Protected against MOPB 29'''

        self._run_script('''
    function checkit($length) {
        if ($length == 0 || $length == 100) {
            echo "Okay ($length)\\n";
            exit(0);
        }
        echo "Bad ($length)\\n";
        exit(1);
    }

  $str = 'S:'.(100*3).':"'.str_repeat('\\61', 100).'"';
  $arr = array(str_repeat('"', 200)."1"=>1,str_repeat('"', 200)."2"=>1);

  $heapdump = unserialize($str);
  checkit(strlen($heapdump));

''')

    def test_mopb_30(self):
        '''Protected against MOPB 30'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("session_register() not available in php 5.4+")

        self._run_script('''
  $shellcode = str_repeat("\\x90", 400);
  $zend_execute_internal = 0x90909090;

  $Hashtable = pack("LLLLLLLLLCCC", 2, 1, 0, 0, 0, $zend_execute_internal, 0, $zend_execute_internal, 0x66666666, 0, 0, 0);

  eval('
  session_start();
  unset($HTTP_SESSION_VARS);
  unset($_SESSION);
  $x = "'.$Hashtable.'";
  session_register($shellcode);');
''')

    def test_mopb_34(self):
        '''Protected against MOPB 34'''

        self._run_script('''
if (mail("test@example.com", "Test\r\n \nAnother-Header: Blub", "Message")===FALSE) {
    echo "Email had injected headers visible\n";
    exit(1);
}
echo "Email was correctly missing injected headers\n";
exit(0);
#''', args=['-d','sendmail_path="bash -c \'grep -q ^Another-Header && exit 1 || exit 0\'"'])

    def test_mopb_41(self):
        '''Protected against MOPB 41'''

        if self.lsb_release['Release'] >= 11.10:
            return self._skipped("sqlite < 3 dropped in 11.10")

        self._run_script('''
    $z = "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU";
    $y = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
    $x = "AQ                                                                        ";
    unset($z);
    unset($y);
    $x = base64_decode($x);

    $y = sqlite_udf_decode_binary($x);

    unset($x);
''')

    def test_mopb_45(self):
        '''Protected against MOPB 45'''

        self._run_script('''
  if (version_compare(phpversion(), "5.2.0")==-1) {
    echo "filter_var does not exist\n";
    exit(0);
  }

  $orig = "test@example.com\n";
  $final = filter_var($orig, FILTER_VALIDATE_EMAIL);

  if ($final === FALSE) {
    echo "Filter detected EOL newline\n";
    exit(0);
  }
  if ($orig == $final) {
    echo "Filter failed to see EOL newline\n";
    exit(1);
  }
  echo "Something odd happened to the filter: '$final' != 'test@example.com'\n";
  exit(1);
''')

    def test_lp_52866(self):
        '''Launchpad #52866'''

        self._run_script('''
  function getLists() {
      $out = array(
  	array(
  	    'id' => 12,
  	    'name' => 'My New List'
  	)
      );
      return $out;
  }

  $opts = Array('uri' => 'urn:http://dapper/lp-52866.php');
  $server = new SoapServer(null, $opts);
  $server->addFunction('getLists');

  $HTTP_RAW_POST_DATA = <<<EOF
<?xml version="1.0" encoding="ISO-8859-1"?>
<SOAP-ENV:Envelope
  SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"
  xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:ns1="urn:http://dapper/lp-52866.php"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:si="http://soapinterop.org/xsd">
  <SOAP-ENV:Body>
    <ns1:getLists>
      <param0 xsi:nil="true"/>
      <param1 xsi:nil="true"/>
      <param2 xsi:nil="true"/>
    </ns1:getLists>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
EOF;

  ob_start();
  $server->handle($HTTP_RAW_POST_DATA);
  $resultxml = ob_get_contents();
  ob_end_clean();

  $expected = array(
      '<item><key xsi:type="xsd:string">id</key><value xsi:type="xsd:int">12</value></item>',
      '<item><key xsi:type="xsd:string">name</key><value xsi:type="xsd:string">My New List</value></item>');

  $simplexml = new SimpleXMLElement($resultxml);
  $items = $simplexml->xpath('//item/item');

  $i = 0;
  foreach($items as $item) {
    $xmllist = explode("\n", $item->asXML());
    $xmlline = "";
    foreach($xmllist as $line) {
      $xmlline = $xmlline . trim($line);
    }
    if (strcmp($expected[$i], $xmlline) != 0) {
      exit(1);
    }
    $i++;
  }

  exit(0);
''')

    def test_lp_239513(self):
        '''Launchpad #239513 -- crash on i386'''

        # FIXME: fix on saucy+
        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Doesn't work on 13.10+")

        # This also breaks because of LP: #1069529

        self._run_script('''
  if (!class_exists('DateTime')) {
    // DateTime didn't exist in php's core in dapper era
    echo "class DateTime does not exist\n";
    exit(0);
  }

  $params = array(new DateTime());

  $params[0] = $params[0]->format(DATE_ISO8601);

  xmlrpc_set_type($params[0], 'datetime');

  exit(0);
''')

    def test_imageCreateTrueColor(self):
        '''imageCreateTrueColor test'''

        self._run_script('''
header ("Content-type: image/png");
$im = imageCreateTrueColor(300,300) or die("Cannot Initialize new GD image stream");

$text_color = imagecolorallocate($im, 233, 14, 91);
imagestring($im, 1, 5, 5,  "A Simple Text String", $text_color);
imagepng($im);
imagedestroy($im);
exit(0);
''')

    def test_cve_2006_7243(self):
        '''Test CVE-2006-7243'''

        expected_str = 'PASS'

        # Based on http://bugs.php.net/bug.php?id=39863

        if self.lsb_release['Release'] < 10.04:
            # fixing CVE-2006-7243 for karmic and earlier 
            # will require php api changes
            self.announce("XFAIL: karmic and earlier are unfixed")
            expected_str = 'FAIL'

        self._check_script_results('''
$filename = "/etc/passwd" . chr(0). ".ridiculous";

if (file_exists($filename))
{
       echo "FAIL: The file [" . $filename . "] exists, but clearly 
shouldn't.\n";
}
else
{
       echo "PASS: The file [" . $filename . "] does not exist.\n";
}
''', expected_str, expected=0)

    def test_cve_2008_3658(self):
        '''test CVE-2008-3658'''

        self._run_script('''
$filename = 'php/cve-2008-3658-font.gdf';
$image = imagecreatetruecolor(50, 20);
$font = imageloadfont($filename);
$black = imagecolorallocate($image, 0, 0, 0);
imagestring($image, $font, 0, 0, "Hello", $black);
exit(0);
''')


    def test_cve_2008_3659(self):
        '''test CVE-2008-3659'''

        self._run_script('''
$res = explode(str_repeat("A",145999999),1);
''',args=['-d','memory_limit=256M'])


    def test_cve_2008_5557(self):
        '''test CVE-2008-5557'''

        self._run_script('''
if (version_compare(phpversion(), "5.1.3")==-1) {
    echo "mb_check_encoding does not exist\n";
    exit(0);
  }

$text = "&''' + '\xc2' + '''%s ASDF ASDF ASDF ASDF ASDF ASDF ASDF";
if( !mb_check_encoding($text,'HTML-ENTITIES') ) {
    $text = htmlentities($text);
}
echo $text;
exit(0);
''')

    def test_cve_2008_5658(self):
        '''test CVE-2008-5658'''

        if self.lsb_release['Release'] == 6.06:
            return self._skipped("Dapper doesn't have ZipArchive")

        zipdir = self.tempdir + '/ziptest'
        os.mkdir(zipdir)

        self._run_script('''
$zip = new ZipArchive;
$res = $zip->open('php/ziptest.zip');
if ($res === TRUE) {
    $zip->extractTo("''' + zipdir + '''");
    $zip->close();
} else {
    echo 'failed, code:' . $res . "\n";
}
''')

        # Make sure the regular files are there
        self.assertTrue(os.path.isfile(zipdir + '/test1.txt'))
        self.assertTrue(os.path.isfile(zipdir + '/test/test2.txt'))

        # Make sure the .. got stripped out of the filename
        self.assertTrue(os.path.isfile(zipdir + '/test3.txt'))
        self.assertFalse(os.path.isfile(self.tempdir + '/test3.txt'))

    def test_cve_2008_5814(self):
        '''test CVE-2008-5814'''

        self._check_script_results('''
setcookie("QRTXSS;QRT", "QRT");
exit(0);
''', 'QRTXSS', invert=True)

    def test_cve_2009_1271(self):
        '''test CVE-2009-1271'''

        if self.lsb_release['Release'] == 6.06:
            return self._skipped("Dapper doesn't have json_decode")

        self._run_script('''
json_decode('[1}');
exit(0);
''')

    def test_cve_2014_1943_1(self):
        '''Test CVE-2014-1943 Part 1'''

        if self.lsb_release['Release'] < 13.10:
            search = "ASCII text"
        else:
            search = "Apple Driver Map"

        bad_contents = "\105\122\000\000\000\000\000"
        filename = os.path.join(self.tempdir, 'cve-2014-1943-1')
        testlib.create_fill(filename, contents=bad_contents)

        self._check_script_results('''
$fi = finfo_open(FILEINFO_NONE);
var_dump(finfo_file($fi, "%s"));
finfo_close($fi);
exit(0);
''' % filename, search)

    def test_cve_2014_1943_2(self):
        '''Test CVE-2014-1943 Part 2'''

        if self.lsb_release['Release'] < 13.10:
            search = "nesting exceeded"
        else:
            search = "Failed identify data"

        bad_contents = "\001" * 250000
        magic = "0           byte        x\n" + \
                ">(1.b)      indirect    x\n"

        filename = os.path.join(self.tempdir, 'cve-2014-1943-2')
        magic_fn = os.path.join(self.tempdir, 'magic')

        testlib.create_fill(filename, contents=bad_contents)
        testlib.create_fill(magic_fn, contents=magic)

        self._check_script_results('''
$fi = finfo_open(FILEINFO_NONE, "%s");
var_dump(finfo_file($fi, "%s"));
finfo_close($fi);
exit(0);
''' % (magic_fn, filename), search)

    def test_cve_2013_7226(self):
        '''Test CVE-2013-7226'''

        if self.lsb_release['Release'] < 13.10:
            return self._skipped("No imagecrop() in 13.04 and earlier")

        self._run_script('''
$img = imagecreatetruecolor(10, 10);
var_dump(imagecrop($img, array("x" => "a", "y" => 0, "width" => 10, "height" => 10)));

$arr = array("x" => "a", "y" => "12b", "width" => 10, "height" => 10);
var_dump(imagecrop($img, $arr));
print_r($arr);

var_dump(imagecrop($img, array("x" => 0, "y" => 0, "width" => -1, "height" => 10)));

var_dump(imagecrop($img, array("x" => -20, "y" => -20, "width" => 10, "height" => 10)));

var_dump(imagecrop($img, array("x" => 0x7fffff00, "y" => 0, "width" => 10, "height" => 10)));
exit(0);
''')

    def test_cve_2009_2687(self):
        '''test CVE-2009-2687'''

        self._run_script('''
exif_read_data("php/hello-s148-cve-2009-2687.jpeg", "FILE,COMPUTED,ANY_TAG");
exit(0);
''')

    def test_cve_2016_454x_1(self):
        '''test CVE-2016-4542, 4543, 4544, part 1'''

        self._check_script_results('''
exif_read_data("php/bug72094_1.jpg");
exit(0);
''', "Invalid JPEG file in")

    def test_cve_2016_454x_2(self):
        '''test CVE-2016-4542, 4543, 4544, part 2'''

        self._check_script_results('''
exif_read_data("php/bug72094_2.jpg");
exit(0);
''', "Invalid JPEG file in")

    def test_cve_2016_454x_3(self):
        '''test CVE-2016-4542, 4543, 4544, part 3'''

        self._check_script_results('''
exif_read_data("php/bug72094_3.jpg");
exit(0);
''', "Invalid JPEG file in")

    def test_cve_2016_454x_4(self):
        '''test CVE-2016-4542, 4543, 4544, part 4'''

        self._check_script_results('''
exif_read_data("php/bug72094_4.jpg");
exit(0);
''', "Invalid JPEG file in")

    def test_cve_2008_7068(self):
        '''test CVE-2008-7068'''

        if self.lsb_release['Release'] >= 13.10:
            return self._skipped("Doesn't work on 13.10+")

        # PoC from http://securityreason.com/achievement_securityalert/58

        # Create the ini file
        tempfile_handle, tempfile = testlib.mkstemp_fill('''
PATH=/
CURR=.
HOME=/home/
''', dir=self.tempdir, suffix='.ini')

        self._run_script('''
$source=dba_open("%s", "wlt", "inifile");
dba_replace("HOME","/www/",$source);
$home=dba_fetch("HOME",$source);
if ($home != "/www/") {
    echo "Value does not appear to be set!\n";
    exit(1);
}
# Try the null byte
dba_replace("\0","/www/",$source);
$home=dba_fetch("HOME",$source);
if ($home != "/www/") {
    echo "Value does not appear to be set!\n";
    exit(1);
}
exit(0);
''' % tempfile)

    def test_cve_2009_2626(self):
        '''test CVE-2009-2626'''

        self._run_script('''
ini_set("error_log","A");
ini_restore("error_log");
exit(0);
''')

    def test_cve_2009_4142(self):
        '''test CVE-2009-4142'''

        self._run_script('''
$bad="&amp";
if (strpos(htmlspecialchars("A\xC0\xAF&",     ENT_QUOTES, 'UTF-8'), $bad) !== false) exit (1);
if (strpos(htmlspecialchars("C\x81\x7f&",     ENT_QUOTES, 'Shift_JIS'), $bad) !== false) exit (1);
if (strpos(htmlspecialchars("E\xA1\xFF&",     ENT_QUOTES, 'EUC-JP'), $bad) !== false) exit (1);
if (strpos(htmlspecialchars("F\x8E\xFF&",     ENT_QUOTES, 'EUC-JP'), $bad) !== false) exit (1);
if (strpos(htmlspecialchars("G\x8F\xA1\xFF&", ENT_QUOTES, 'EUC-JP'), $bad) !== false) exit (1);
exit(0);
''')

    def test_cve_2010_0397(self):
        '''test CVE-2010-0397'''

        self._run_script('''
$req = '<?xml version="1.0"?>
<methodCall>
   </methodCall>';
    $result = xmlrpc_decode_request( $req, $frop );
exit(0);
''')

    def test_cve_2014_9705(self):
        '''test CVE-2014-9705'''

        self._run_script('''
$tag = 'en_US';
$r = enchant_broker_init();
$d = enchant_broker_request_dict($r, $tag);
enchant_dict_quick_check($d, 'one', $suggs);
$d = enchant_broker_request_dict($r, $tag);
enchant_dict_quick_check($d, 'one', $suggs);
$d = enchant_broker_request_dict($r, $tag);
exit(0);
''')

    def test_cve_2010_1866(self):
        '''test CVE-2010-1866'''

        testdir = self.tempdir + '/CVE-2010-1866'
        os.mkdir(testdir)

        self._run_script('''
$x = '0fffffffe

XXX';
file_put_contents("file://%s/test.dat",$x);
$y = file_get_contents('php://filter/read=dechunk/resource=file://%s/test.dat');
exit(0);
''' % (testdir,testdir))

    def test_cve_2010_1868(self):
        '''test CVE-2010-1868'''

        if self.lsb_release['Release'] < 11.10:
            # sqlite v2 version of the script
            self._run_script('''
$dh = sqlite_popen("%s/whatever");
str_repeat("A",39); // +1 byte for \x00
$dummy = sqlite_single_query($dh," ");
exit(0);
''' %(self.tempdir))
        else:
            self._run_script('''
$dh = new SQLite3("%s/whatever");
str_repeat("A",39); // +1 byte for \x00
$dummy = $dh->query(" ");
exit(0);
''' %(self.tempdir))

    def test_cve_2010_2225(self):
        '''test CVE-2010-2225'''

        if self.lsb_release['Release'] >= 12.10:
            expected = 0
        else:
            expected = 255

        # Based on code found here: http://blog.nibbles.fr/?p=1837
        self._run_script('''
$fakezval = pack('IIII',0x08048000,0x0000000f,0x00000000,0x00000005);
$objst = unserialize('C:16:"SplObjectStorage":73:{x:i:3;O:8:"stdClass":0:{},s:4:"AAAA";;r:1;,s:4:"BBBB";;r:3;,R:2;;m:a:0:{}}');
$objst->rewind();$objst->next();
 
for($i = 0; $i < 5; $i++) {
	$v[$i]=$fakezval.$i;
}
exit(0);
''', expected=expected)

    def test_cve_2010_2531(self):
        '''test CVE-2010-2531'''

        if self.lsb_release['Release'] >= 13.04:
            return self._skipped("Reproducer doesn't work on Raring+")

        self._check_script_results('''
@$obj->p =& $obj;
var_export($obj, true);
exit(0);
''', "'p' =>", expected=255, invert=True)

        self._check_script_results('''
@$obj->p =& $obj;
var_export($obj, true);
exit(0);
''', "Fatal error", expected=255)

        self._check_script_results('''
$a[] =& $a;
var_export($a, true);
exit(0);
''', "0 =>", expected=255, invert=True)

        self._check_script_results('''
$a[] =& $a;
var_export($a, true);
exit(0);
''', "Fatal error", expected=255)

    def test_cve_2010_3709(self):
        '''Test CVE-2010-3709'''

        if self.lsb_release['Release'] == 6.06:
            return self._skipped("Dapper doesn't have ZipArchive")

        # based on http://securityreason.com/achievement_securityalert/90
        zipfile, zippath = testlib.mkstemp_fill('', suffix='zip', dir=self.tempdir)
        zipfile.close()
        self._run_script('''
$zip = new ZipArchive;
$zip->open("%s");
$zip->getArchiveComment();
exit(0);
''' %(zippath))

    def test_cve_2012_6113(self):
        '''Test CVE-2012-6113'''

        if self.lsb_release['Release'] == 8.04:
            return self._skipped("Hardy doesn't have openssl_encrypt()")

        self._run_script('''
  $length = strlen(openssl_encrypt('', 'aes-256-cbc', 'blahblah', true, openssl_random_pseudo_bytes(16)));
if ($length > 16) {
    exit(1);
}
    exit(0);
''')

    def test_cve_2010_3710(self):
        '''Test CVE-2010-3710'''

        if self.lsb_release['Release'] == 6.06:
            return self._skipped("Dapper doesn't have FILTER_VALIDATE_EMAIL")

        self._check_script_results('''
var_dump(filter_var('valid@email.address', FILTER_VALIDATE_EMAIL));
''', 'string(19) "valid@email.address"', expected=0)

        self._check_script_results('''
// Beyond the allowable limit for an e-mail address.
var_dump(filter_var('xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy.zz', FILTER_VALIDATE_EMAIL))
''', 'bool(false)', expected=0)

        self._check_script_results('''
// An invalid address likely to crash PHP due to stack exhaustion if it goes to
// the validation regex.
var_dump(filter_var(str_repeat('x', 8000), FILTER_VALIDATE_EMAIL));
''', 'bool(false)', expected=0)

    def test_cve_2010_3870(self):
        '''Test CVE-2010-3870'''

        testlist = [
            ('"\\x41\\xC2\\x3E\\x42"', "413f3e42"),
            ('"\\xE3\\x80\\x22"', "3f22"),
            ('"\\x41\\x98\\xBA\\x42\\xE2\\x98\\x43\\xE2\\x98\\xBA\\xE2\\x98"', "413f3f423f433f3f")
        ]

        for value, result in testlist:
            self._check_script_results('''
echo bin2hex(utf8_decode(%s)), "\n";
''' %(value), result, expected=0)

    def test_cve_2010_4156(self):
        '''Test CVE-2010-4156'''

        self._check_script_results('''
mb_internal_encoding("ISO-8859-1");
var_dump(bin2hex(mb_strcut("abc", 0, 32)));
''', 'string(6) "616263"', expected=0)

    def test_curl_null_byte(self):
        '''Test Curl null byte injection'''

        self._check_script_results('''
$url = "file:///etc/passwd\0http://google.com";
$ch = curl_init();
var_dump(curl_setopt($ch, CURLOPT_URL, $url));
''', 'Curl option contains invalid characters', expected=0)

    def test_cve_2014_3669(self):
        '''Test CVE-2014-3669, integer overflow in unserialize()'''

        self._check_script_results('''
echo unserialize('C:3:"XYZ":18446744075857035259:{}');
''', 'Insufficient data for unserializing', expected=0)

    def test_cve_2014_3670(self):
        '''Test CVE-2014-3670, heap corruption in exif_thumbnail()'''

        self._check_script_results('''
var_dump(exif_thumbnail("php/CVE-2014-3670.jpg"));
''', 'File structure corrupted', expected=0)

    def test_cve_2010_4645(self):
        '''Test CVE-2010-4645, x87 DoS'''

        try:
            testlib.timeout(5, self._check_script_results, '''
print 2.2250738585072011e-308;
''', "2.2250738585", 0)
        except testlib.TimedOutException:
            assert(False)

    def test_cve_2010_4698(self):
        '''Test CVE-2010-4698 segv in gd'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("imagepsloadfont() not available on Quantal+")

        # based on http://seclists.org/fulldisclosure/2010/Dec/180
        self._check_script_results('''
$img = imagecreatetruecolor(1, 1); //Arbitrary
$fnt = imagepsloadfont("data/c0419bt_.pfb"); //Arbitrary
//The final parameter is the number of anti-aliasing steps
imagepstext($img, "Testing", $fnt, 0xAAAAAA, 0xAAAAAA, 0xAAAAAA, 0xAAAAAA, 0xAAAAAA, 0, 0, 0.0, 100);
''', 'Antialias steps must be', expected=0)

    def test_cve_2011_0421(self):
        '''Test CVE-2011-0421 segv when handling zips'''

        # Based on https://bugzilla.redhat.com/show_bug.cgi?id=688735
        if self.lsb_release['Release'] == 6.06:
            return self._skipped("Dapper did not have ziparchive")

        zipfile, zippath = testlib.mkstemp_fill('', suffix='zip', dir=self.tempdir)
        zipfile.close()
        self._run_script('''
$nx=new ZipArchive();
$nx->open("%s");
$nx->locateName("a",ZIPARCHIVE::FL_UNCHANGED);
''' %(zippath))

    def test_cve_2011_0441(self):
        '''Test CVE-2011-0441 cron race'''

        if not os.path.exists("/etc/cron.d/"+app):
            return self._skipped("Couldn't find php cron script for some reason")

        f = open("/etc/cron.d/"+app)

        for line in f:
            if line[0] != "#" and re.search("\|.*xargs.*rm", line):
                self.assertTrue(False, "Found buggy cleanup cron job elements")
        f.close()

    def test_cve_2011_0708(self):
        '''Test CVE-2011-0708 exif crash'''

        # Based on testcases from
        # http://svn.php.net/viewvc?view=revision&revision=308316

        self._run_script('''
exif_read_data('php/cve-2011-0708-bug54002_1.jpeg');
exif_read_data('php/cve-2011-0708-bug54002_2.jpeg');
''')

    def test_cve_2011_1153(self):
        '''Test CVE-2011-1153'''

        # Based on https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2011-1153
        if self.lsb_release['Release'] < 10.04:
            return self._skipped("Karmic and earlier don't have PHAR")

        self._check_script_results('''
$x = new PharData('%s/CVE-2011-1153.php');
$x->loadPhar("%%08x.%%08x.%%08x.%%08x.%%08x");
''' %(self.tempdir), '"%08x.%08x.%08x.%08x.%08x"', expected=255)

    def test_cve_2011_1464(self):
        '''Test CVE-2011-1464'''

        # Based on http://bugs.php.net/bug.php?id=54055
        self._check_script_results('''
for($i = 500; $i <= 1074; $i++) {
  ini_set('precision', $i);
  print "$i\n";
  strval(pow(2, -1074));
}
''', '1074', expected=0)

    def test_cve_2014_8142(self):
        '''Test CVE-2014-8142'''

        self._run_script('''
for ($i=4; $i<100; $i++) {
	$m = new StdClass();

	$u = array(1);

	$m->aaa = array(1,2,&$u,4,5);
	$m->bbb = 1;
	$m->ccc = &$u;
	$m->ddd = str_repeat("A", $i);

	$z = serialize($m);
	$z = str_replace("bbb", "aaa", $z);
	$y = unserialize($z);
	$z = serialize($y);
}
''')

    def test_cve_2015_0231(self):
        '''Test CVE-2015-0231'''

        self._run_script('''
for ($i=4; $i<100; $i++) {
    $m = new StdClass();

    $u = array(1);

    $m->aaa = array(1,2,&$u,4,5);
    $m->bbb = 1;
    $m->ccc = &$u;
    $m->ddd = str_repeat("A", $i);

    $z = serialize($m);
    $z = str_replace("aaa", "123", $z);
    $z = str_replace("bbb", "123", $z);
    $y = unserialize($z);
    $z = serialize($y);
}
''')

    def test_cve_2015_0232(self):
        '''Test CVE-2015-0232'''

        self._run_script('''
/*
* Pollute the heap. Helps trigger bug. Sometimes not needed.
*/
class A {
    function __construct() {
        $a = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa';
        $this->a = $a . $a . $a . $a . $a . $a;
    }
};

function doStuff ($limit) {

    $a = new A;

    $b = array();
    for ($i = 0; $i < $limit; $i++) {
        $b[$i] = clone $a;
    }

    unset($a);

    gc_collect_cycles();
}

$iterations = 3;

doStuff($iterations);
doStuff($iterations);

gc_collect_cycles();

print_r(exif_read_data("php/CVE-2015-0232.jpg"));
''')

    def test_bug69441(self):
        '''Test PHP bug 69441 (CVE pending)'''

        self._check_script_results('''
$fname = 'php/bug69441.phar';
try {
$r = new Phar($fname, 0);
} catch(UnexpectedValueException $e) {
	echo $e;
}
''', 'phar error: corrupted central directory entry,'
     ' no magic signature in zip-based phar', expected=0)

    def test_cve_2016_4342(self):
        '''Test CVE-2016-4342'''

        self._check_script_results('''
try {
$phar = new PharData("php/bug71354.tar");
var_dump($phar['aaaa']->getContent());
} catch(Exception $e) {
  echo $e->getMessage();
}
''', 'string(0) ""', expected=0)

    def test_cve_2016_4343(self):
        '''Test CVE-2016-4343'''

        self._check_script_results('''
try {
$phar = new PharData("php/bug71331.tar");
var_dump($phar['aaaa']->getContent());
} catch(Exception $e) {
  echo $e->getMessage();
}
''', 'is a corrupted tar file', expected=0)

    def test_cve_2015_2783(self):
        '''Test CVE-2015-2783'''

        self._check_script_results('''
try {
$p = new Phar('php/bug69324.phar', 0);
$meta=$p->getMetadata();
var_dump($meta);
} catch(Exception $e) {
	echo $e->getMessage();
}
''', 'internal corruption of phar', expected=0)

    def test_cve_2015_7803(self):
        '''Test CVE-2015-7803'''

        self._check_script_results('''
try {
$p = new Phar('php/CVE-2015-7803.phar', 0);
echo $p->getMetadata();
foreach (new RecursiveIteratorIterator($p) as $file) {
  $temp="";
  $temp= $file->getFileName() . "\n";
  $temp.=file_get_contents($file->getPathName()) . "\n"; // display contents
  var_dump($file->getMetadata());
}
} catch(Exception $e) {
  echo $e->getMessage();
}
''', 'is not a file in phar', expected=0)

    def test_cve_2015_7804(self):
        '''Test CVE-2015-7804'''

        self._check_script_results('''
try {
$phar = new PharData("php/CVE-2015-7804.zip");
var_dump($phar);
$meta = $phar->getMetadata();
var_dump($meta);
} catch(Exception $e) {
  echo $e->getMessage();
}
''', 'end of central directory not found', expected=0)

    def test_cve_2016_2554(self):
        '''Test CVE-2016-2554'''

        # return code flip-flops between 0 and 255
        handle, name = testlib.mkstemp_fill('''<?php
$p = new PharData("php/CVE-2016-2554.tar");
$newp = $p->decompress("test");
?>
''')
        rc, report = testlib.cmd(['/usr/bin/'+app], stdin = handle)

        result = 'Got exit code %d, expected 0 or 255\n' % rc
        self.assertTrue(rc == 0 or rc == 255, result + report)
        os.unlink(name)

    def test_cve_2016_3142(self):
        '''Test CVE-2016-3142'''

        self._check_script_results('''
try {
$phar = new PharData("php/CVE-2016-3142.zip");
} catch(UnexpectedValueException $e) {
	echo $e->getMessage();
}
''', 'end of central directory not found', expected=0)

    def test_cve_2014_9652(self):
        '''Test CVE-2014-9652'''

        if self.lsb_release['Release'] >= 16.04:
            search = 'JPEG image data, Exif standard'
        else:
            search = 'JPEG image data, EXIF standard'

        self._check_script_results('''
	$test_file = "php/CVE-2014-3670.jpg";
	$f = new finfo;

	var_dump($f->file($test_file));
var_dump(exif_thumbnail("php/CVE-2014-9652.jpg"));
''', search, expected=0)

    def test_cve_2015_3411_1(self):
        '''Test CVE-2015-3411_1'''

        self._check_script_results('''
$doc = new DOMDocument();
$doc->load('/etc/fonts/fonts.conf' . chr(0) . 'somethingelse.xml');
$r = $doc->saveXML();
$pos = strpos($r, 'font');
if ($pos == false) {
   echo "looks ok\n";
   exit(0);
} else {
   echo "insecure\n";
   exit(1);
}
''', 'looks ok', expected=0)

    def test_cve_2015_3411_2(self):
        '''Test CVE-2015-3411_2'''

        if self.lsb_release['Release'] == 12.04:
            search = ""
        else:
            search = 'expects parameter 1 to be a valid path'

        testfile = self.tempdir + '/testfile'
        self._check_script_results('''
xmlwriter_open_uri("''' + testfile + '''". chr(0) . "foobar.xml");
''', search, expected=0)

        self.assertFalse(os.path.exists(testfile))

    def test_cve_2015_3411_3(self):
        '''Test CVE-2015-3411_3'''

        self._check_script_results('''
$f=finfo_open(FILEINFO_NONE);
echo finfo_file($f, '/etc/passwd' . chr(0) . 'foobar.txt');
''', 'Invalid path', expected=0)

    def test_cve_2015_3411_4(self):
        '''Test CVE-2015-3411_4'''

        self._check_script_results('''
var_dump(
  hash_hmac_file('md5', '/etc/passwd', 'secret')
  ===
  hash_hmac_file('md5', '/etc/passwd' . chr(0) . 'foobar', 'secret')
);
''', 'Invalid path', expected=0)

    def test_cve_2015_4021(self):
        '''Test CVE-2015-4021'''

        self._check_script_results('''
$fname = 'php/CVE-2015-4021.tar.phar';
$r = new Phar($fname, 0);
''', 'is a corrupted tar file', expected=255)

    def test_cve_2015_4025_1(self):
        '''Test CVE-2015-4025_1'''

        if self.lsb_release['Release'] == 12.04:
            search = "bool(false)"
        else:
            search = 'expects parameter 1 to be a valid path'

        self._check_script_results('''
var_dump(set_include_path("/path/to/php\0extra"));
echo get_include_path()."\n";
''', search, expected=0)

    def test_cve_2015_4025_2(self):
        '''Test CVE-2015-4025_2'''

        if self.lsb_release['Release'] == 12.04:
            search = "bool(false)"
        else:
            search = 'expects parameter 2 to be a valid path'

        self._check_script_results('''
var_dump(tempnam("/tmp/", "prefix\0extra"));
''', search, expected=0)

    def test_cve_2015_4025_3(self):
        '''Test CVE-2015-4025_3'''

        if self.lsb_release['Release'] == 12.04:
            search = "bool(false)"
        else:
            search = 'expects parameter 1 to be a valid path'

        self._check_script_results('''
var_dump(rmdir("/tmp/foo\0extra"));
''', search, expected=0)

    def test_cve_2015_4025_4(self):
        '''Test CVE-2015-4025_4'''

        if self.lsb_release['Release'] == 12.04:
            search = "bool(false)"
        else:
            search = 'expects parameter 1 to be a valid path'

        self._check_script_results('''
var_dump(readlink("/bin/sh\0extra"));
''', search, expected=0)

    def test_cve_2015_4147(self):
        '''Test CVE-2015-4147'''

        self._check_script_results('''
$dummy = unserialize('O:10:"SoapClient":3:{s:3:"uri";s:1:"a";s:8:"location";s:22:"http://localhost/a.xml";s:17:"__default_headers";i:1337;}');
var_dump($dummy->whatever());
''', 'Uncaught SoapFault exception', expected=255)

    def test_cve_2015_4598_1(self):
        '''Test CVE-2015-4598_1'''

        if self.lsb_release['Release'] == 12.04:
            search = ""
        else:
            search = 'expects parameter 1 to be a valid path'

        testfile = self.tempdir + '/testfile'
        self._check_script_results('''
$d = new DOMDocument();
$d->loadHTMLFile("/etc/issue");
$d->save("''' + testfile + '''". chr(0) . "extra");
''', search, expected=0)

        self.assertFalse(os.path.exists(testfile))

    def test_cve_2015_4598_2(self):
        '''Test CVE-2015-4598_2'''

        if self.lsb_release['Release'] == 12.04:
            search = ""
        else:
            search = 'expects parameter 1 to be a valid path'

        testfile = self.tempdir + '/testfile'
        self._check_script_results('''
$d = new DOMDocument();
$d->loadHTMLFile("/etc/issue");
$d->saveHTMLFile("''' + testfile + '''". chr(0) . "extra");
''', search, expected=0)

        self.assertFalse(os.path.exists(testfile))

    def test_cve_2015_4599(self):
        '''Test CVE-2015-4599'''

        self._check_script_results('''
$data = 'O:9:"SoapFault":4:{s:9:"faultcode";i:4298448493;s:11:"faultstring";i:4298448543;s:7:"'."\0*\0".'file";i:4298447319;s:7:"'."\0*\0".'line";s:4:"ryat";}';
echo unserialize($data);
''', 'SoapFault exception', expected=0)

    def test_cve_2016_5399(self):
        '''Test CVE-2015-5399'''

        self._run_script('''
$fp = bzopen('php/CVE-2016-5399.bz2', 'r');
if ($fp === FALSE) {
    exit("ERROR: bzopen()");
}
$data = "";
while (!feof($fp)) {
    $res = bzread($fp);
    if ($res === FALSE) {
        exit("ERROR: bzread()");
    }
    $data .= $res;
}
bzclose($fp);
''', expected=0)

    def test_cve_2016_6291(self):
        '''Test CVE-2016-6291'''

        self._check_script_results('''
var_dump(count(exif_read_data('php/CVE-2016-6291.jpeg')));
''', 'IFD data bad offset', expected=0)

    def test_cve_2016_6292(self):
        '''Test CVE-2016-6292'''

        self._check_script_results('''
var_dump(count(exif_read_data('php/CVE-2016-6292.jpg')));
''', 'IFD data bad offset', expected=0)

    def test_cve_2015_2787(self):
        '''Test CVE-2015-2787'''

        self._run_script('''
class evilClass {
	public $name;
	function __wakeup() {
		unset($this->name);
	}
}

$fakezval = pack(
    'IIII',
    0x00100000,
    0x00000400,
    0x00000000,
    0x00000006 
);

$data = unserialize('a:2:{i:0;O:9:"evilClass":1:{s:4:"name";a:2:{i:0;i:1;i:1;i:2;}}i:1;R:4;}');

for($i = 0; $i < 5; $i++) {
    $v[$i] = $fakezval.$i;
}

#var_dump($data);

#echo gettype($data[1])

if (gettype($data[1]) == "integer") exit(0);
exit(1);
''')


#    def test_cve_2011_1657(self):
#        '''Test CVE-2011-1657'''
#
#        # based on https://bugs.php.net/bug.php?id=54681
#        zipfile, zippath = testlib.mkstemp_fill('', suffix='zip', dir=self.tempdir)
#        zipfile.close()
#        self._run_script('''
#$nx=new ZipArchive();
#$nx->open("%s");
#$nx->addGlob(str_repeat("*",333333),0x39);
#''' %(zippath))

    def test_cve_2011_4566(self):
        '''Test CVE-2011-4566 exif crash'''

        self._run_script('''
exif_read_data('php/cve-2011-4566-sample.jpg');
''')

    # This test is flaky
    def disabled_test_cve_2011_4153(self):
        '''Test CVE-2011-4153 failure to check zend_strdup() result'''

        '''Based on https://bugs.php.net/bug.php?id=55748'''

        contents = '''
define(str_repeat("A",$argv[1]),"a");
'''
        # yuck, python doesn't return -ENOMEM
        expected = 255;
        trigger_val = 1999999;
        handle, name = testlib.mkstemp_fill('<?php\n'+contents+'\n?>\n')

        # yuck
        rc = 0
        while rc in [0, 1] and trigger_val < (512 * 1000000):
            rc, report = testlib.cmd(['sh', '-c', 'ulimit -m 128000 ; ulimit -v 128000 ; /usr/bin/'+app+' %s %d' %(name, trigger_val)])
            trigger_val += 1000000

        os.unlink(name)

        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, 'Out of memory')

    def test_cve_2012_0781(self):
        '''Test CVE-2012-0781 tidy module null ptr deref'''

        '''Based on https://bugs.php.net/bug.php?id=54682'''

        # Warnings like "PHP Warning:  tidy::__construct(): Cannot Load
        # '*' into memory  in /home/ubuntu/pleep.php on line 2" are okay,
        # but this should not segv (return error code 11)
        self._run_script('''
$x = new Tidy("*");
$x->diagnose();
''')

    def test_cve_2013_2110(self):
        '''Test CVE-2013-2110 quoted_printable_encode heap overflow'''

        self._run_script('''
quoted_printable_encode(str_repeat("\xf4", 1000));
''')

    def test_cve_2013_4113(self):
        '''Test CVE-2013-4113 xml parser heap overflow'''

        self._run_script('''
xml_parse_into_struct(xml_parser_create_ns(), str_repeat("<blah>", 1000), $a);
''')

    def test_cve_2013_4248(self):
        '''Test CVE-2013-4248 Null-byte certificate handling'''

        # http://git.php.net/?p=php-src.git;a=commit;h=dcea4ec698dcae39b7bba6f6aa08933cbfee6755

        self._run_script('''$cert = "-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----";
$info = openssl_x509_parse($cert);
if ($info['extensions']['subjectAltName'] ==
'DNS:altnull.python.org' . "\0" . 'example.com, email:null@python.org' . "\0" . 'user@example.org, URI:http://null.python.org' . "\0" . 'http://example.org, IP Address:192.0.2.1, IP Address:2001:DB8:0:0:0:0:0:1
') {
echo "OK\n";
exit(0);
}
echo "BAD\n";
exit(1);
''')

    def test_cve_2013_6420(self):
        '''Test CVE-2013-6420'''

        # http://git.php.net/?p=php-src.git;a=commit;h=c1224573c773b6845e83505f717fbf820fc18415

        self._run_script('''$cert = "-----BEGIN CERTIFICATE-----
MIIEpDCCA4ygAwIBAgIJAJzu8r6u6eBcMA0GCSqGSIb3DQEBBQUAMIHDMQswCQYD
VQQGEwJERTEcMBoGA1UECAwTTm9yZHJoZWluLVdlc3RmYWxlbjEQMA4GA1UEBwwH
S8ODwrZsbjEUMBIGA1UECgwLU2VrdGlvbkVpbnMxHzAdBgNVBAsMFk1hbGljaW91
cyBDZXJ0IFNlY3Rpb24xITAfBgNVBAMMGG1hbGljaW91cy5zZWt0aW9uZWlucy5k
ZTEqMCgGCSqGSIb3DQEJARYbc3RlZmFuLmVzc2VyQHNla3Rpb25laW5zLmRlMHUY
ZDE5NzAwMTAxMDAwMDAwWgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAXDTE0MTEyODExMzkzNVowgcMxCzAJBgNVBAYTAkRFMRwwGgYDVQQIDBNO
b3JkcmhlaW4tV2VzdGZhbGVuMRAwDgYDVQQHDAdLw4PCtmxuMRQwEgYDVQQKDAtT
ZWt0aW9uRWluczEfMB0GA1UECwwWTWFsaWNpb3VzIENlcnQgU2VjdGlvbjEhMB8G
A1UEAwwYbWFsaWNpb3VzLnNla3Rpb25laW5zLmRlMSowKAYJKoZIhvcNAQkBFhtz
dGVmYW4uZXNzZXJAc2VrdGlvbmVpbnMuZGUwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDDAf3hl7JY0XcFniyEJpSSDqn0OqBr6QP65usJPRt/8PaDoqBu
wEYT/Na+6fsgPjC0uK9DZgWg2tHWWoanSblAMoz5PH6Z+S4SHRZ7e2dDIjPjdhjh
0mLg2UMO5yp0V797Ggs9lNt6JRfH81MN2obXWs4NtztLMuD6egqpr8dDbr34aOs8
pkdui5UawTZksy5pLPHq5cMhFGm06v65CLo0V2Pd9+KAokPrPcN5KLKebz7mLpk6
SMeEXOKP4idEqxyQ7O7fBuHMedsQhu+prY3si3BUyKfQtP5CZnX2bp0wKHxX12DX
1nfFIt9DbGvHTcyOuN+nZLPBm3vWxntyIIvVAgMBAAGjQjBAMAkGA1UdEwQCMAAw
EQYJYIZIAYb4QgEBBAQDAgeAMAsGA1UdDwQEAwIFoDATBgNVHSUEDDAKBggrBgEF
BQcDAjANBgkqhkiG9w0BAQUFAAOCAQEAG0fZYYCTbdj1XYc+1SnoaPR+vI8C8CaD
8+0UYhdnyU4gga0BAcDrY9e94eEAu6ZqycF6FjLqXXdAboppWocr6T6GD1x33Ckl
VArzG/KxQohGD2JeqkhIMlDomxHO7ka39+Oa8i2vWLVyjU8AZvWMAruHa4EENyG7
lW2AagaFKFCr9TnXTfrdxGVEbv7KVQ6bdhg5p5SjpWH1+Mq03uR3ZXPBYdyV8319
o0lVj1KFI2DCL/liWisJRoof+1cR35Ctd0wYBcpB6TZslMcOPl76dwKwJgeJo2Qg
Zsfmc2vC1/qOlNuNq/0TzzkVGv8ETT3CgaU+UXe4XOVvkccebJn2dg==
-----END CERTIFICATE-----";
$info = openssl_x509_parse($cert);
if ($info['issuer']['emailAddress'] != "stefan.esser@sektioneins.de") {
echo "BAD\n";
exit(1);
}
if ($info["validFrom_time_t"] != -1) {
echo "BAD\n";
exit(1);
}
echo "OK\n";
exit(0);
''')

    def test_xmlrpc_encode(self):
        '''Test xmlrpc_encode_request'''

        output = '''<?xml version="1.0" encoding="iso-8859-1"?>
<methodCall>
<methodName>system.methodHelp</methodName>
<params>
 <param>
  <value>
   <string>system.methodSignature</string>
  </value>
 </param>
</params>
</methodCall>'''

        self._check_script_results('''
$params = "system.methodSignature";
$method = "system.methodHelp";
$request = xmlrpc_encode_request($method,$params);
echo ( $request );
''', output, expected=0)

    def test_crypt_des(self):
        '''Test crypt des'''

        '''Ensure DES crypt() call returns something valid'''
        # based on https://bugs.php.net/bug.php?id=55439
        self._check_script_results('''
printf("DES: %s\n", crypt('password', 'rl'));
''', 'DES: rl0uE0e2WKB0.', expected=0)

    def test_crypt_extended_des(self):
        '''Test crypt extended des'''

        '''Ensure extended DES crypt() call returns something valid'''

        expected = 'extDES: _1234salta8K5xg/q5NE'

        # no extended DES in php 5.2.x
        if self.lsb_release['Release'] == 8.04:
            expected = 'extDES: _1bWQa5GoloMQ'

        self._check_script_results('''
printf("extDES: %s\n", crypt('password', '_1234salt'));
''', expected, expected=0)

    def test_crypt_md5(self):
        '''Test crypt md5 (CVE-2011-3189)'''

        '''Ensure MD5 crypt() call returns something valid'''
        # based on https://bugs.php.net/bug.php?id=55439
        self._check_script_results('''
printf("MD5: %s\n", crypt('password', '$1$U7AjYB.O$'));
''', 'MD5: $1$U7AjYB.O$L1N7ux7twaMIMw0En8UUR1', expected=0)

    def test_crypt_blowfish(self):
        '''Test crypt blowfish'''

        '''Ensure blowfish crypt() call returns something valid'''
        # output tested against the following perl invocation
        # perl -e 'use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64);  print bcrypt("password", "\$2a\$15\$" . en_base64("saltedsaltedsalt") . "\$");'
        expected = 'blowfish: $2a$15$a0DqbETia0DqbETia0Dqb.6WhoRkHvwhfwbzVLTAErmK7hPP0SDMO'

        # no blowfish in 8.04
        if self.lsb_release['Release'] == 8.04:
            expected = 'blowfish: $2mV0NZp92R3g'

        self._check_script_results('''
printf("blowfish: %s\n", crypt('password', '$2a$15$a0DqbETia0DqbETia0Dqb.$'));
''', expected, expected=0)

    def test_crypt_blowfish_CVE_2011_2483(self):
        '''Test crypt blowfish CVE-2011-2483'''

        '''Ensure blowfish w/8-bit chars crypt() call returns correct
        values (CVE-2011-2483)'''

        # output tested against the following perl invocation
        # perl -e 'use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64);  print bcrypt("pas£word", "\$2a\$05\$" . en_base64("saltedsaltedsalt") . "\$");'
        expected = 'blowfish-8bit: $2a$05$a0DqbETia0DqbETia0Dqb.vQI8ImwKEJ/V5Kb2M2jTuD5pAFjSyDm'

        # no blowfish in 8.04
        if self.lsb_release['Release'] == 8.04:
            expected = 'blowfish-8bit: $2V5x5yqOHzB.'

        self._check_script_results('''
printf("blowfish-8bit: %s\n", crypt('pas£word', '$2a$05$a0DqbETia0DqbETia0Dqb.$'));
''', expected, expected=0)

    def test_crypt_sha256(self):
        '''Test crypt sha256'''

        '''Ensure SHA256 crypt() call returns something valid'''
        self._check_script_results('''
printf("SHA256: %s\n", crypt('password', '$5$mRrJxSZ0$'));
''', 'SHA256: $5$mRrJxSZ0$znYVdXPXDy9axJR.WY0NsPHt3/fjgiuEbPXtFuM0It4', expected=0)

    def test_crypt_sha512(self):
        '''Test crypt sha512'''

        '''Ensure SHA512 crypt() call returns something valid'''
        self._check_script_results('''
printf("SHA512: %s\n", crypt('password', '$6$mRrJxSZ0$'));
''', 'SHA512: $6$mRrJxSZ0$nXoUx1CfEmdhZxjYW/hiseO3Ti.zDjdyU2.TkCtnalp/QNnmmB.ECDqMI0Z99YV6HvfPUR0rOyUlM564cEs5B0', expected=0)

    def test_crypt_sha512_CVE_2012_2317(self):
        '''Test crypt sha512 CVE-2012-2317'''

        '''calling crypt() with no salt should return something'''
        self._run_script('''
$output = crypt('password', False);
printf("SHA512: %s\n", $output);
if ('' === $output) exit(1);
''')

    def test_lp_776642(self):
        '''Test segv when using get/set (lp: #776642)'''

        self._check_script_results('''
class CausesBug
{
	protected $_fields = array();
	public function __set($key, $value)
	{
		$this->_fields[$key] = $value;
	}
	public function __isset($key)
	{
		return isset($this->_fields[$key]);
	}
}

$document = new CausesBug();

print __LINE__ . "\n";
add_tags_to_document($document);
print __LINE__ . "\n";
add_taxonomy_to_document($document);
print __LINE__ . "\n";

function add_tags_to_document(&$document) {
  $x = 'a';
  if (!isset($document->a)) {
      $document->a = '';
  }
}

function add_taxonomy_to_document(&$document) {
  print __LINE__ . "\n";
}
''', '24', expected=0)

    def test_open_basedir_restrictions(self):
        '''Test open_basedir (lp: #701896)'''

        handle, datafile = testlib.mkstemp_fill('''
1 2 3 4
''', dir=self.tempdir)
        handle.close()

        configs = [
            # allowed loose config
            ('1 2 3 4', 'open_basedir = /home/:%s:/usr/lib/%s/:/usr/share/phpmyadmin/:/etc/phpmyadmin/:/var/lib/phpmyadmin/\n' % (self.tempdir, app)),
            # allowed config (breakage of lp# 701896)
            ('1 2 3 4', 'open_basedir = /home/:%s:/usr/lib/%s/:/usr/share/phpmyadmin/:/etc/phpmyadmin/:/var/lib/phpmyadmin/\n' % (self.tempdir + '/', app)),
            # disallowed config, changed with the fix in USN-1042-1 for
            # CVE-2010-3436; see also  http://bugs.php.net/bug.php?id=53597
            ('open_basedir restriction in effect', 'open_basedir = /home/:%s:/usr/lib/%s/:/usr/share/phpmyadmin/:/etc/phpmyadmin/:/var/lib/phpmyadmin/\n' % (self.tempdir[0:-3], app)),
            # denied config
            ('open_basedir restriction in effect', 'open_basedir = /home/:/usr/lib/%s/:/usr/share/phpmyadmin/:/etc/phpmyadmin/:/var/lib/phpmyadmin/\n' % (app)),
        ]

        for output, config in configs:
            fd, config_path = testlib.mkstemp_fill(config, suffix=".ini", prefix="config-", dir=self.tempdir)
            fd.close()
            self._check_script_results('''
$contents = file_get_contents("%s");
echo $contents;
''' %(datafile), output, expected=0, args=['-c', config_path])

    def test_magic_quotes_regression(self):
        '''Test magic_quotes_gpc regression (lp: #930115)'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("magic_quotes not in php 5.4 and higher")

        configs = [
            # magic_quotes_gpc disabled
            ('string(0) ""', 'magic_quotes_gpc = Off'),
            # magic_quotes_gpc enabled (breakage from lp: #930115)
            ('string(1) "1"', 'magic_quotes_gpc = On'),
        ]

        for output, config in configs:
            fd, config_path = testlib.mkstemp_fill(config, suffix=".ini", prefix="config-", dir=self.tempdir)
            fd.close()
            self._check_script_results('''
echo "Dumping the value of magic_quotes_gpc ini setting:\n";
var_dump(ini_get("magic_quotes_gpc"));
''', output, expected=0, args=['-c', config_path])

    def test_magic_quotes_function(self):
        '''Test magic_quotes_gpc function'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("magic_quotes not in php 5.4 and higher")

        configs = [
            # magic_quotes_gpc disabled
            ('0', 'magic_quotes_gpc = Off'),
            # magic_quotes_gpc enabled (breakage from lp: #930115)
            ('1', 'magic_quotes_gpc = On'),
        ]

        for output, config in configs:
            fd, config_path = testlib.mkstemp_fill(config, suffix=".ini", prefix="config-", dir=self.tempdir)
            fd.close()
            self._check_script_results('''
echo "Querying get_magic_quotes_gpc():\n";
echo get_magic_quotes_gpc();
echo "\n";
''', output, expected=0, args=['-c', config_path])

    def test_exif(self):
        '''Test exif image parsing'''

        self._run_script('''
$image = 'data/exif-data.jpg';

# Test imagetype
if (exif_imagetype($image) != IMAGETYPE_JPEG) {
    echo "Could not parse imagetype!";
    exit(1);
}

# Test headers
$exif = exif_read_data($image, 'IFD0');
if ($exif===false) {
    echo "Could not parse header data!";
    exit(1);
}

$exif = exif_read_data($image, 'IFD0', 0);
if (($exif['Make'] != "Canon") ||
    ($exif['Model'] != "Canon PowerShot A570 IS")) {
    echo "Some IFD0 values don't match!";
    exit(1);
}

exit(0);
''')

class PEARTest(testlib.TestlibCase):
    '''Test basic PEAR functionality for php'''

    def setUp(self):
        '''Setup mechanisms'''
        expected = 0
        rc, report = testlib.cmd(['pear', 'config-get', 'cache_dir'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self.saved_cachedir = report
        self.cachedir = tempfile.mkdtemp(prefix='pear-cache')

        rc, report = testlib.cmd(['pear', 'config-set', 'cache_dir', self.cachedir + '/cache'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def tearDown(self):
        '''Shutdown methods'''

        # restore cachedir
        expected = 0
        rc, report = testlib.cmd(['pear', 'config-set', 'cache_dir', self.saved_cachedir])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        if os.path.exists(self.cachedir):
            shutil.rmtree(self.cachedir)

    def test_pear_config(self):
        '''Test pear config-show command'''

        expected = 0
        rc, report = testlib.cmd(['pear', 'config-show'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_pear_list(self):
        '''Test pear list command'''

        expected = 0
        rc, report = testlib.cmd(['pear', 'list'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, 'Archive_Tar')
        self._word_find(report, 'PEAR')

    def test_pear_list_all(self):
        '''Test pear list-all command (needs remote network access)'''

        if self.lsb_release['Release'] == 6.06:
            return self._skipped("pear remote ops are busticated on Dapper")

        expected = 0
        rc, report = testlib.cmd(['pear', 'list-all'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, 'Archive_Tar')
        self._word_find(report, 'PEAR')

    def test_pear_simple(self):
        '''Test pear simple install/uninstall'''

        if self.lsb_release['Release'] == 6.06:
            return self._skipped("pear install is busticated on Dapper")

        expected = 0
        rc, initial_list = testlib.cmd(['pear', 'list'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + initial_list)

        rc, report = testlib.cmd(['pear', 'install', 'php/Benchmark-1.2.8.tgz' ])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['pear', 'list'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, 'Benchmark')

        rc, report = testlib.cmd(['pear', 'uninstall', 'Benchmark' ])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd(['pear', 'list'])
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self._word_find(report, 'Benchmark', invert=True)

class PHPApacheTest(testlib_httpd.HttpdCommon):
    '''Test basic php functionality with apache'''
    def setUp(self):
        '''Setup mechanisms'''
        self.ports_file = "/etc/apache2/ports.conf"
        self.testlib_conf = "/etc/apache2/conf.d/testlib"
        self.php_mod = "/etc/apache2/mods-available/"+app+".load"
        if app == "php5":
            self.php_ini = "/etc/php5/apache2/php.ini"
        else:
            self.php_ini = "/etc/php/7.0/apache2/php.ini"

        if self.lsb_release['Release'] >= 12.10:
            self.default_site = "/etc/apache2/sites-available/000-default.conf"
        else:
            self.default_site = "/etc/apache2/sites-available/default"
        self.release = testlib.ubuntu_release()

        # Change the default port, so we can run in a schroot
        testlib.config_replace(self.ports_file, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.ports_file])
        testlib.config_replace(self.default_site, "", append=True)
        if self.lsb_release['Release'] > 8.04:
            subprocess.call(['sed', '-i', 's/80/8000/g', self.default_site])
        else:
            subprocess.call(['sed', '-i', 's/\(VirtualHost \*\)/\\1\:8000/', self.default_site])

        testlib_httpd.HttpdCommon._setUp(self)


    def tearDown(self):
        '''Shutdown methods'''
        if os.path.exists(self.testlib_conf):
            os.unlink(self.testlib_conf)
        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.default_site)
        testlib.config_restore(self.php_ini)

        testlib_httpd.HttpdCommon._tearDown(self)

    def adjust_php_setting(self, config, value):
        '''modify a php setting'''

        '''This possibly should get shoved into testlib_httpd'''
        testlib.config_replace(self.php_ini, "", append=True)
        subprocess.call(['sed', '-i', 's/^ *\(' + config + '\) *=.*/\1 = ' + value + '/', self.php_ini])

    def test_daemons(self):
        '''Test daemon'''
        if self.lsb_release['Release'] >= 13.10:
            pidfile = "/var/run/apache2/apache2.pid"
        else:
            pidfile = "/var/run/apache2.pid"
        self.assertTrue(testlib.check_pidfile("apache2", pidfile))

    def test_status(self):
        '''Test status (apache2ctl)'''
        rc, report = testlib.cmd(['apache2ctl', 'status'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_http(self):
        '''Test http'''
        self._test_url("http://localhost:8000/")

        test_str = testlib_httpd.create_html_page(self.html_page)
        self._test_url("http://localhost:8000/" + \
                       os.path.basename(self.html_page), test_str)

    def test_php(self):
        '''Test php'''

        if self.lsb_release['Release'] >= 16.04:
            self._disable_mod("mpm_event", restart=False)
            self._enable_mod("mpm_prefork")

        self._enable_mod(app)
        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url("http://localhost:8000/" + \
                       os.path.basename(self.php_page), test_str)

    def test_php_CVE_2011_4885(self):
        '''Test CVE_2011_4885'''

        if self.lsb_release['Release'] >= 16.04:
            self._disable_mod("mpm_event", restart=False)
            self._enable_mod("mpm_prefork")

        self._enable_mod(app)
        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f1023f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?"
        for i in range(1,1026):
            request += "f" + str(i) + "f=g&"
        self._test_url(request, "NULL")

    def test_php_CVE_2011_4885_part2(self):
        '''Test CVE_2011_4885 part 2'''

        if self.lsb_release['Release'] >= 16.04:
            self._disable_mod("mpm_event", restart=False)
            self._enable_mod("mpm_prefork")

        self._enable_mod(app)
        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f42f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?"
        for i in range(1,1026):
            request += "f" + str(i) + "f=g&"
        self._test_url(request, 'string(1) "g"')

    def test_magic_quotes_default(self):
        '''Test magic_quotes_gpc default setting'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("magic_quotes not in php 5.4 and higher")

        self._enable_mod(app)

        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?f=O'Re\"ill%5Cy"
        if self.lsb_release['Release'] == 8.04:
            # hardy defaults to safe quotes = On
            self._test_url(request, '''string(13) "O\\\'Re\\\"ill\\\\y"''')
        else:
            self._test_url(request, '''string(10) "O\'Re\"ill\\y"''')

    def test_magic_quotes_functionality(self):
        '''Test magic_quotes_gpc functionality'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("magic_quotes not in php 5.4 and higher")

        self.adjust_php_setting("magic_quotes_gpc", "On")
        self._enable_mod(app)

        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?f=O'Re\"ill%5Cy"
        self._test_url(request, '''string(13) "O\\\'Re\\\"ill\\\\y"''')

    def test_CVE_2012_1823(self):
        '''Test CVE-2012-1823'''

        '''URL arguments that begin with '-' and don't contain '='
        should not be processed as command line arguments by php5-cgi'''
        if self.lsb_release['Release'] >= 16.04:
            self._disable_mod("mpm_event", restart=False)
            self._enable_mod("mpm_prefork")

        self._enable_mod(app)
        test_str = testlib_httpd.create_php_page(self.php_page, 'var_dump(ini_get("allow_url_include"));')
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?-s"
        # we should *not* get the source with this request
        self._test_url(request, test_str, invert=True)

    def test_CVE_2012_2311(self):
        '''Test CVE-2012-2311'''

        test_str = testlib_httpd.create_php_page(self.php_page, 'var_dump(ini_get("allow_url_include"));')
        self.adjust_php_setting("allow_url_include", "Off")
        if self.lsb_release['Release'] >= 16.04:
            self._disable_mod("mpm_event", restart=False)
            self._enable_mod("mpm_prefork")

        self._enable_mod(app)

        # ensure that allow_url_include is disabled
        request = "http://localhost:8000/" + os.path.basename(self.php_page)
        self._test_url(request, 'string(1) "0"')

        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?-dallow_url_include%3dOn"
        # we should *not* be setting allow_url_include to On with this
        self._test_url(request, 'string(1) "0"')

class PHPApacheCGITest(testlib_httpd.HttpdCommon):
    '''Test basic php functionality with apache'''

    def setUp(self):
        '''Setup mechanisms'''
        self.ports_file = "/etc/apache2/ports.conf"
        self.testlib_conf = "/etc/apache2/conf.d/testlib"
        self.php_mod = "/etc/apache2/mods-available/"+app+".load"
        if app == "php5":
            self.php_ini = "/etc/php5/cgi/php.ini"
        else:
            self.php_ini = "/etc/php/7.0/cgi/php.ini"
        if self.lsb_release['Release'] >= 13.10:
            self.default_site = "/etc/apache2/sites-available/000-default.conf"
        else:
            self.default_site = "/etc/apache2/sites-available/default"
        self.release = testlib.ubuntu_release()

        # Change the default port, so we can run in a schroot
        testlib.config_replace(self.ports_file, "", append=True)
        subprocess.call(['sed', '-i', 's/80/8000/g', self.ports_file])
        testlib.config_replace(self.default_site, """

<IfModule mod_actions.c>
        Action application/x-httpd-php /cgi-bin/%s
</IfModule>
""" % app, append=True)
        if self.lsb_release['Release'] > 8.04:
            subprocess.call(['sed', '-i', 's/80/8000/g', self.default_site])
        else:
            subprocess.call(['sed', '-i', 's/\(VirtualHost \*\)/\\1\:8000/', self.default_site])

        testlib_httpd.HttpdCommon._setUp(self)
        self._disable_mod(app)
        self._enable_mods(["cgi", "actions"])

        if self.lsb_release['Release'] >= 13.10:
            self._enable_confs([app+"-cgi"])
        elif self.lsb_release['Release'] >= 12.10:
            self._enable_mods([app+"_cgi"])

    def tearDown(self):
        '''Shutdown methods'''
        if os.path.exists(self.testlib_conf):
            os.unlink(self.testlib_conf)
        testlib.config_restore(self.ports_file)
        testlib.config_restore(self.default_site)
        testlib.config_restore(self.php_ini)
        if self.lsb_release['Release'] >= 13.10:
            self._disable_confs([app+"-cgi"])
        elif self.lsb_release['Release'] >= 12.10:
            self._disable_mods([app+"_cgi"])
        self._disable_mods(["actions", "cgi"])

        testlib_httpd.HttpdCommon._tearDown(self)

    def adjust_php_setting(self, config, value):
        '''modify a php setting'''

        '''This possibly should get shoved into testlib_httpd'''
        testlib.config_replace(self.php_ini, "", append=True)
        subprocess.call(['sed', '-i', 's/^ *\(' + config + '\) *=.*/\1 = ' + value + '/', self.php_ini])

    def test_php(self):
        '''Test php (CGI)'''
        test_str = testlib_httpd.create_php_page(self.php_page)
        self._test_url("http://localhost:8000/" + \
                       os.path.basename(self.php_page), test_str)

    def test_php_CVE_2011_4885(self):
        '''Test CVE_2011_4885 (CGI)'''

        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f1023f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?"
        for i in range(1,1026):
            request += "f" + str(i) + "f=g&"
        self._test_url(request, "NULL")

    def test_php_CVE_2011_4885_part2(self):
        '''Test CVE_2011_4885 part 2 (CGI)'''

        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f42f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?"
        for i in range(1,1026):
            request += "f" + str(i) + "f=g&"
        self._test_url(request, 'string(1) "g"')

    def test_magic_quotes_default(self):
        '''Test magic_quotes_gpc default setting (CGI)'''

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("magic_quotes not in php 5.4 and higher")

        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?f=O'Re\"ill%5Cy"
        if self.lsb_release['Release'] == 8.04:
            # hardy defaults to safe quotes = On
            self._test_url(request, '''string(13) "O\\\'Re\\\"ill\\\\y"''')
        else:
            self._test_url(request, '''string(10) "O\'Re\"ill\\y"''')

    def disabled_test_magic_quotes_functionality(self):
        '''Test magic_quotes_gpc functionality (CGI)'''

        # This test simply fails on 10.04 and 12.04, need to investigate

        if self.lsb_release['Release'] >= 12.10:
            return self._skipped("magic_quotes not in php 5.4 and higher")

        self.adjust_php_setting("magic_quotes_gpc", "On")

        test_str = testlib_httpd.create_php_page(self.php_page, "var_dump($_GET['f']);")
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?f=O'Re\"ill%5Cy"
        self._test_url(request, '''string(13) "O\\\'Re\\\"ill\\\\y"''')

    def test_CVE_2012_1823(self):
        '''Test CVE-2012-1823 (CGI)'''

        '''URL arguments that begin with '-' and don't contain '='
        should not be processed as command line arguments by php5-cgi'''
        test_str = testlib_httpd.create_php_page(self.php_page, 'var_dump(ini_get("allow_url_include"));')
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?-s"
        # we should *not* get the source with this request
        self._test_url(request, test_str, invert=True)

    def test_CVE_2012_2311(self):
        '''Test CVE-2012-2311 (CGI)'''

        if self.lsb_release['Release'] <= 12.04:
            return self._skipped("test fails on 10.04 and 12.04, need to investigate")

        test_str = testlib_httpd.create_php_page(self.php_page, 'var_dump(ini_get("allow_url_include"));')
        self.adjust_php_setting("allow_url_include", "Off")

        # ensure that allow_url_include is disabled
        request = "http://localhost:8000/" + os.path.basename(self.php_page)
        self._test_url(request, 'string(1) "0"')

        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?-dallow_url_include%3dOn"
        # we should *not* be setting allow_url_include to On with this
        self._test_url(request, 'string(1) "0"')

    def test_CVE_2012_2336(self):
        '''Test CVE-2012-2336 (CGI)'''

        '''DoS via benchmarking argument to php5-cgi'''
        test_str = testlib_httpd.create_php_page(self.php_page)

        # ensure that allow_url_include is disabled
        request = "http://localhost:8000/" + os.path.basename(self.php_page) + "?-T100"
        # we should *not* be setting allow_url_include to On with this
        self._test_url(request, 'Content-type: text/html', invert=True)

if __name__ == '__main__':
    # You can run this normally, which will run php5, or run it for php7.0
    # by specifying php7.0 on the command line. Alternatively, you can
    # also use the test-php7.0.py test script.
    if (len(sys.argv) == 1 or sys.argv[1] == '-v'):
        app = 'php5'
    else:
        app = sys.argv[1]
        del sys.argv[1]

    # hack to get the global variable in the PhpPrivateTests module
    __builtin__.app = app

    print "Using binary: %s" % app

    # more configurable
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PHPTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PEARTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PHPApacheTest))
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PHPApacheCGITest))

    # Pull in private tests
    if use_private:
        suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PhpPrivateTests))

    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
