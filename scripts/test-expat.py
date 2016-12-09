#!/usr/bin/python
#
#    test-expat.py quality assurance test script for expat
#    Copyright (C) 2010-2016 Canonical Ltd.
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
# QRT-Packages: expat tar
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/expat.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install expat tar && ./test-expat.py -v'
'''

import unittest, sys
import testlib
import os
import tempfile
import shutil

try:
    from private.qrt.expat import PrivateExpatTest
except ImportError:
    class PrivateExpatTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class ExpatTest(testlib.TestlibCase, PrivateExpatTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="expat-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_xmlts(self):
        '''Test XML Test Suite (1800+ tests)'''
        version = "20080827"

        shutil.copy('./data/xmlts%s.tar.gz' % version, self.tempdir)
        os.chdir(self.tempdir)
        (rc, report) = testlib.cmd(["tar", "zxf", 'xmlts%s.tar.gz' % version])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # based on tests/xmltest.sh from expat 2.0.1
        os.mkdir(os.path.join('out'))
        contents = '''#! /bin/sh
MYDIR="./"
cd "$MYDIR"
MYDIR="`pwd`"
XMLWF="/usr/bin/xmlwf"
TS="$MYDIR"
OUTPUT="$TS/out/"

# RunXmlwfNotWF file reldir
# reldir includes trailing slash
RunXmlwfNotWF() {
  file="$1"
  reldir="$2"
  $XMLWF -p "$file" > outfile || return $?
  read outdata < outfile
  if test "$outdata" = "" ; then
      echo "Expected well-formed: $reldir$file"
      return 1
  else
      return 0
  fi
}

# RunXmlwfWF file reldir
# reldir includes trailing slash
RunXmlwfWF() {
  file="$1"
  reldir="$2"
  $XMLWF -p -d "$OUTPUT$reldir" "$file" > outfile || return $?
  read outdata < outfile
  if test "$outdata" = "" ; then
      if [ -f "out/$file" ] ; then
          diff "$OUTPUT$reldir$file" "out/$file" > outfile
          if [ -s outfile ] ; then
              cp outfile "$OUTPUT$reldir$file.diff"
              echo "Output differs: $reldir$file"
              return 1
          fi
      fi
      return 0
  else
      echo "In $reldir: $outdata"
      return 1
  fi
}

SUCCESS=0
ERROR=0

UpdateStatus() {
  if [ "$1" -eq 0 ] ; then
    SUCCESS=`expr $SUCCESS + 1`
  else
    ERROR=`expr $ERROR + 1`
  fi
}

##########################
# well-formed test cases #
##########################

cd "$TS/xmlconf"
for xmldir in ibm/valid/P* \
              ibm/invalid/P* \
              xmltest/valid/ext-sa \
              xmltest/valid/not-sa \
              xmltest/invalid \
              xmltest/invalid/not-sa \
              xmltest/valid/sa \
              sun/valid \
              sun/invalid ; do
  cd "$TS/xmlconf/$xmldir"
  mkdir -p "$OUTPUT$xmldir"
  for xmlfile in *.xml ; do
      RunXmlwfWF "$xmlfile" "$xmldir/"
      UpdateStatus $?
  done
  rm outfile
done

cd "$TS/xmlconf/oasis"
mkdir -p "$OUTPUT"oasis
for xmlfile in *pass*.xml ; do
    RunXmlwfWF "$xmlfile" "oasis/"
    UpdateStatus $?
done
rm outfile

##############################
# not well-formed test cases #
##############################

cd "$TS/xmlconf"
for xmldir in ibm/not-wf/P* \
              ibm/not-wf/misc \
              xmltest/not-wf/ext-sa \
              xmltest/not-wf/not-sa \
              xmltest/not-wf/sa \
              sun/not-wf ; do
  cd "$TS/xmlconf/$xmldir"
  for xmlfile in *.xml ; do
      RunXmlwfNotWF "$xmlfile" "$xmldir/"
      UpdateStatus $?
  done
  rm outfile
done

cd "$TS/xmlconf/oasis"
for xmlfile in *fail*.xml ; do
    RunXmlwfNotWF "$xmlfile" "oasis/"
    UpdateStatus $?
done
rm outfile

echo "Passed: $SUCCESS"
echo "Failed: $ERROR"

'''
        script = os.path.join(self.tempdir, 'test.sh')
        open(script,'w').write(contents)
        (rc, report) = testlib.cmd(["sh", script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected_output = []
        # these fail in both 0.95.8 and 2.0.1
        expected_output.append("Output differs: ibm/valid/P02/ibm02v01.xml")
        expected_output.append("Output differs: ibm/valid/P28/ibm28v02.xml")
        expected_output.append("Output differs: ibm/valid/P29/ibm29v01.xml")
        expected_output.append("Output differs: ibm/valid/P29/ibm29v02.xml")
        expected_output.append("Output differs: ibm/valid/P54/ibm54v01.xml")
        expected_output.append("Output differs: ibm/valid/P56/ibm56v08.xml")
        expected_output.append("Output differs: ibm/valid/P57/ibm57v01.xml")
        expected_output.append("Output differs: ibm/valid/P58/ibm58v01.xml")
        expected_output.append("Output differs: ibm/valid/P58/ibm58v02.xml")
        expected_output.append("Output differs: ibm/valid/P70/ibm70v01.xml")
        expected_output.append("Output differs: ibm/valid/P82/ibm82v01.xml")
        expected_output.append("ibm49i02.dtd: No such file or directory")
        expected_output.append("Output differs: ibm/invalid/P58/ibm58i01.xml")
        expected_output.append("Output differs: ibm/invalid/P58/ibm58i02.xml")
        expected_output.append("Output differs: xmltest/valid/sa/069.xml")
        expected_output.append("Output differs: xmltest/valid/sa/076.xml")
        expected_output.append("Output differs: xmltest/valid/sa/090.xml")
        expected_output.append("Output differs: xmltest/valid/sa/091.xml")
        expected_output.append("Output differs: sun/valid/not-sa01.xml")
        expected_output.append("Output differs: sun/valid/not-sa02.xml")
        expected_output.append("Output differs: sun/valid/not-sa03.xml")
        expected_output.append("Output differs: sun/valid/not-sa04.xml")
        expected_output.append("Output differs: sun/valid/notation01.xml")
        expected_output.append("Output differs: sun/valid/sa02.xml")
        expected_output.append("Output differs: sun/valid/sa03.xml")
        expected_output.append("Output differs: sun/valid/sa04.xml")
        expected_output.append("Output differs: sun/valid/sa05.xml")
        expected_output.append("Expected well-formed: ibm/not-wf/misc/432gewf.xml")
        expected_output.append("Expected well-formed: xmltest/not-wf/not-sa/005.xml")
        expected_output.append("Expected well-formed: sun/not-wf/uri01.xml")
        expected_output.append("Expected well-formed: oasis/p06fail1.xml")
        expected_output.append("Expected well-formed: oasis/p08fail1.xml")
        expected_output.append("Expected well-formed: oasis/p08fail2.xml")

        if self.lsb_release['Release'] >= 8.04: # additional output for expat 2.0.1
            expected_output.append("Passed: 1775")
            expected_output.append("Failed: 33")
        else: # additional output for expat 1.95.8
            expected_output.append("003.ent: Invalid argument")
            expected_output.append("010.ent: Invalid argument")
            expected_output.append("001.ent: Invalid argument")
            expected_output.append("003-2.ent: Invalid argument")
            expected_output.append("null.ent: Invalid argument")
            expected_output.append("p31pass1.dtd: Invalid argument")
            expected_output.append("050.xml: Invalid argument")
            expected_output.append("p39fail3.xml: Invalid argument")
            expected_output.append("Expected well-formed: xmltest/not-wf/sa/050.xml")
            expected_output.append("Expected well-formed: oasis/p39fail3.xml")
            expected_output.append("Passed: 1767")
            expected_output.append("Failed: 41")

        result = ""
        for line in expected_output:
            if line not in report:
                result += "Couldn't find '%s' in report\n" % (line)
        self.assertTrue(result == "", result + report + '\nThis script is known to work with expat 2.0.1 and 1.95.8')

if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
