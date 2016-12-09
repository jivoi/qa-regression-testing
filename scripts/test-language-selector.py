#!/usr/bin/python
#
#    test-language-selector.py quality assurance test script for language-selector
#    Copyright (C) 2010 Canonical Ltd.
#    Author: 
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# packages required for test to run:
# QRT-Packages: dbus sudo
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: 
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install dbus sudo && sudo ./test-language-selector.py -v'

    How to run in a clean schroot named 'lucid':
    $ schroot -c lucid -u root -- sh -c 'apt-get -y install dbus sudo && ./test-language-selector.py -v'
'''


import unittest, sys, os
import testlib

try:
    from private.qrt.LanguageSelector import PrivateLanguageSelectorTest
except ImportError:
    class PrivateLanguageSelectorTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LanguageSelectorTest(testlib.TestlibCase, PrivateLanguageSelectorTest):
    '''Test my thing.'''

    def _readLanguage(self):
        lines = [x.split('"')[1] for x in open('/etc/default/locale').readlines() if x.startswith('LANGUAGE="')]
        language = ""
        if len(lines) > 0:
            language = lines[0]
        return language

    def setUp(self):
        '''Set up prior to each test_* function'''

    def tearDown(self):
        '''Clean up after each test_* function'''

    def test_dbus_escape(self):
        '''Actually checks PolicyKit return code (CVE-2011-0729)'''

        before = self._readLanguage()

        expected = 'AMROOT'
        if self.lsb_release['Release'] < 10.10:
            self._skipped("only Maverick and later")
            expected = before

	# Cannot change language (with spaces) without root privs...
        testlib.cmd(['sudo','-u',os.environ['SUDO_USER'],'dbus-send','--system','--print-reply','--dest=com.ubuntu.LanguageSelector','/','com.ubuntu.LanguageSelector.SetSystemDefaultLanguageEnv','string:EVIL EVIL" more evil "xyz'])
        after_evil = self._readLanguage()
	# Cannot change language (without spaces) without root privs...
        testlib.cmd(['sudo','-u',os.environ['SUDO_USER'],'dbus-send','--system','--print-reply','--dest=com.ubuntu.LanguageSelector','/','com.ubuntu.LanguageSelector.SetSystemDefaultLanguageEnv','string:AMNOTROOT'])
        after_amnotroot = self._readLanguage()
	# Can change language (without spaces) with root privs...
        testlib.cmd(['dbus-send','--system','--print-reply','--dest=com.ubuntu.LanguageSelector','/','com.ubuntu.LanguageSelector.SetSystemDefaultLanguageEnv','string:AMROOT'])
        after_amroot = self._readLanguage()
	# Cannot change language (with spaces) with root privs...
        testlib.cmd(['dbus-send','--system','--print-reply','--dest=com.ubuntu.LanguageSelector','/','com.ubuntu.LanguageSelector.SetSystemDefaultLanguageEnv','string:AMROOT WITH SPACES'])
        after_amroot_spaces = self._readLanguage()
	# Attempt to restore original value...
        testlib.cmd(['dbus-send','--system','--print-reply','--dest=com.ubuntu.LanguageSelector','/','com.ubuntu.LanguageSelector.SetSystemDefaultLanguageEnv','string:%s' % (before)])
        after = self._readLanguage()
        self.assertEquals(before, after_evil)
        self.assertEquals(before, after_amnotroot)
        self.assertEquals(expected, after_amroot)
        self.assertEquals(expected, after_amroot_spaces)
        self.assertEquals(before, after)

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
