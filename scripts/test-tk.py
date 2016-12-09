#!/usr/bin/python
#
#    test-tk.py quality assurance test script for Tk
#    Copyright (C) 2008 Canonical Ltd.
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
  How to run in a clean virtual machine:
    1. apt-get -y install tk8.4 tk8.5
    2. apt-get -y install tk8.0 (dapper only)
    3. ./test-tk.py
'''

# QRT-Depends: data
# QRT-Packages: tk8.4 tk8.5
# QRT-Alternates: tk8.3


import unittest, os
import testlib

class TkTest(testlib.TestlibCase):
    '''Test tk functionality.'''

    def _run_script(self, contents, versions, expected=0, args=[]):
        '''Run a tk script, expecting exit code 0'''
        for ver in versions:
            handle, name = testlib.mkstemp_fill(contents+'\n')
            self.assertShellExitEquals(expected, ['/usr/bin/wish%s' % ver] + args, stdin = handle)
            os.unlink(name)

    def test_a_simple_application(self):
        '''Simple "Hello World" application'''

        if self.lsb_release['Release'] >= 11.10:
            versions = [8.4, 8.5]
        else:
            versions = [8.3, 8.4, 8.5]

        self._run_script('''
wm title . "hi!"
button .hello -text "Hello, World!"
pack .hello
after 1000 exit
''', versions)

    def test_gif(self):
        '''Test loading a GIF image'''

        if self.lsb_release['Release'] >= 11.10:
            versions = [8.4, 8.5]
        else:
            versions = [8.3, 8.4, 8.5]

        self._run_script('''
image create photo picture -file ./data/well-formed.gif
canvas .c
pack .c
 .c create image 1 1 -anchor nw -image picture -tag "GIF test"
after 1000 exit
''', versions)

    def test_cve_2008_0553(self):
        '''Test for CVE-2008-0553 segfault'''

        if self.lsb_release['Release'] >= 11.10:
            versions = [8.4, 8.5]
        else:
            versions = [8.3, 8.4, 8.5]

        self._run_script('''
image create photo -data {
R0lGODlhCgAKAPcAAAAAAIAAAACAAICAAAAAgIAAgACAgICAgMDAwP8AAAD/
AP//AAAA//8A/wD//////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAMwAAZgAAmQAAzAAA/wAzAAAzMwAzZgAzmQAzzAAz/wBmAABmMwBmZgBm
mQBmzABm/wCZAACZMwCZZgCZmQCZzACZ/wDMAADMMwDMZgDMmQDMzADM/wD/
AAD/MwD/ZgD/mQD/zAD//zMAADMAMzMAZjMAmTMAzDMA/zMzADMzMzMzZjMz
mTMzzDMz/zNmADNmMzNmZjNmmTNmzDNm/zOZADOZMzOZZjOZmTOZzDOZ/zPM
ADPMMzPMZjPMmTPMzDPM/zP/ADP/MzP/ZjP/mTP/zDP//2YAAGYAM2YAZmYA
mWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZmzGZm/2aZ
AGaZM2aZZmaZmWaZzGaZ/2bMAGbMM2bMZmbMmWbMzGbM/2b/AGb/M2b/Zmb/
mWb/zGb//5kAAJkAM5kAZpkAmZkAzJkA/5kzAJkzM5kzZpkzmZkzzJkz/5lm
AJlmM5lmZplmmZlmzJlm/5mZAJmZM5mZZpmZmZmZzJmZ/5nMAJnMM5nMZpnM
mZnMzJnM/5n/AJn/M5n/Zpn/mZn/zJn//8wAAMwAM8wAZswAmcwAzMwA/8wz
AMwzM8wzZswzmcwzzMwz/8xmAMxmM8xmZsxmmcxmzMxm/8yZAMyZM8yZZsyZ
mcyZzMyZ/8zMAMzMM8zMZszMmczMzMzM/8z/AMz/M8z/Zsz/mcz/zMz///8A
AP8AM/8AZv8Amf8AzP8A//8zAP8zM/8zZv8zmf8zzP8z//9mAP9mM/9mZv9m
mf9mzP9m//+ZAP+ZM/+ZZv+Zmf+ZzP+Z///MAP/MM//MZv/Mmf/MzP/M////
AP//M///Zv//mf//zP///yH5BAEAABAALAAAAAAKAAoAABUSAAD/HEiwoMGD
CBMqXMiwYcKAADs=
}
exit
''', versions)

if __name__ == '__main__':
    unittest.main()

