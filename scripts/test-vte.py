#!/usr/bin/python -u
#
#    test-vte.py quality assurance test script for vte
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Kees Cook <kees@ubuntu.com>
#
# I haven't figured out how to set stdin to unbuffered without using the
# "-u" python command line argument above.  It would be nice to fix this...
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
# QRT-Packages: gnome-terminal
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/VTE.py
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege:

'''
    This test expects to be run within an active VTE session, like in
    gnome-terminal.

    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install gnome-terminal  && ./test-vte.py -v'
'''


import unittest, sys, time
import testlib
import select
import tty
import termios

WINDOW_CODE = 21
ICON_CODE = 20

try:
    from private.qrt.VTE import PrivateVTETest
except ImportError:
    class PrivateVTETest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class VTETest(testlib.TestlibCase, PrivateVTETest):
    '''Test my thing.'''

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def _stdin_ready(self):
        return select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], [])

    def _write_window_title(self, title):
        sys.stdout.write('\x1b]2;%s\a' % (title))
        sys.stdout.flush()

    def _read_title(self, code=WINDOW_CODE):
        termios_attr = termios.tcgetattr(sys.stdin)
        tty.setcbreak(sys.stdin.fileno())

        header = '\x1b]'
        footer = '\x1b\\'

        sys.stdout.write('\x1b[%dt' % (code))
        sys.stdout.flush()
        timeout = 100
        response = ''
        while timeout > 0:
            while self._stdin_ready():
                response += sys.stdin.read(1)

            if header in response and footer in response:
                break
            time.sleep(0.1)
            timeout -= 1

        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, termios_attr)

        self.assertTrue(response != '', "Did not read any response")
        title = response.split(header)[1].split(footer)[0]
        if title[0] in ['l','L']:
            title = title[1:]
        self.assertFalse(title == '', "Did not read any title")

        return title

    def test_title_set_read(self):
        '''Window title cannot be read back (CVE-2010-2713)'''

        evil_title = "Evil Title Here"
        old_title = self._read_title()
        self.assertNotEqual(evil_title, old_title, "Window title did not reset")

        self._write_window_title(evil_title)

        # Looks like doing the set/get too quickly can race, so read back
        # twice to let terminal emulator finish processing.
        new_title = self._read_title()
        new_title = self._read_title()
        self.assertEqual(old_title, new_title, "'%s' != '%s'" % (old_title, new_title))

    def test_icon_title_read(self):
        '''Icon title is just "Terminal"'''

        self.assertEqual('Terminal', self._read_title(code=ICON_CODE))

if __name__ == '__main__':
    # simple
    unittest.main()
