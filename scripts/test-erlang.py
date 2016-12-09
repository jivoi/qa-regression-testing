#!/usr/bin/python
#
#    test-erlang.py quality assurance test script for erlong
#    Copyright (C) 2010 Canonical Ltd.
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
# QRT-Packages: erlang-base
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 

'''
    To run:
    $ sudo apt-get install erlang-base
    $ ./test-erlang.py -v

    TODO:
    - a *ton*. This script only tests a few very simple things and is meant
      to test regressions in patched parts of erlang. Ideally the test suite
      would be run in the build. See:
      http://www.erlang.org/cgi-bin/ezmlm-cgi?2:msn:1488:ikamdokeffmgahaocnkg
'''


import unittest, sys, os
import testlib
import tempfile

try:
    from private.qrt.Erlang import PrivateErlangTest
except ImportError:
    class PrivateErlangTest(object):
        '''Empty class'''
    #print >>sys.stdout, "Skipping private tests"

class ErlangTest(testlib.TestlibCase, PrivateErlangTest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = ""

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def _run_script(self, contents, expected, expected_out, args=[]):
        '''Run "contents" as script'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        script = os.path.join(self.tmpdir, "runme")
        testlib.create_fill(script, contents, mode=0755)
        rc, report = testlib.cmd([script] + args)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = "Got output:\n%s\nExpected \n%s" % (report, expected_out)
        self.assertEquals(expected_out, report, result)

    def test_hello(self):
        '''Test hello world'''
        contents = '''#!/usr/bin/env escript
-export([main/1]).

main(X) ->
    io:format("Hello world~nX=~p~n", [X]).
'''
        expected_out = '''Hello world
X=["1","2"]
'''
        self._run_script(contents, 0, expected_out, ['1', '2'])

    def test_factorial(self):
        '''Test factorial'''
        contents = '''#!/usr/bin/env escript
main([X]) ->
    J = list_to_integer(X),
    N = fac(J),
    io:format("factorial ~w = ~w~n",[J, N]).

fac(0) -> 1;
fac(N) ->
    N * fac(N-1).
'''
        expected_out = '''factorial 87 = 2107757298379527717213600518699389595229783738061356212322972511214654115727593174080683423236414793504734471782400000000000000000000
'''
        self._run_script(contents, 0, expected_out, ['87'])

    def test_CVE_2008_2371(self):
        '''Test CVE-2008-2371'''
        contents = '''#!/usr/bin/env escript
-export([main/1]).

main(X) ->
    re:compile(<<"(?i)[\xc3\xa9\xc3\xbd]|[\xc3\xa9\xc3\xbdA]">>, [unicode]),
    io:format("ok=~p~n", [X]).
'''
        expected_out = '''ok=["SUCCESS"]
'''
        self._run_script(contents, 0, expected_out, ['SUCCESS'])


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
