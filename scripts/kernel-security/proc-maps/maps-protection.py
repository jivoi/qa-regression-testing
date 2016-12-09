#!/usr/bin/env python
#
# This verifies that memory-segment listing /proc files (maps, smaps) are
# not world-readable, and that setuid priv-dropped process can still read
# their own maps files.
#
# (At some point, the maps_protect knob became useless?)
#
# Copyright (C) 2008, 2013 Canonical, Ltd.
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv3
from __future__ import print_function

import errno
import os
import time
import unittest
from subprocess import Popen, PIPE, STDOUT


def maps_readable(pid, command=None, expected=None):
    readable = True
    output = []
    filenames = ['/proc/%s/maps' % pid, '/proc/%s/smaps' % pid]
    if not pid == "self":
        filenames.extend(['/proc/%s/task/%s/maps' % (pid, pid), '/proc/%s/task/%s/smaps' % (pid, pid)])
    for filename in filenames:
        count = 0
        try:
            if command is None:
                contents = open(filename).read()
            else:
                contents = Popen([command, filename], stdout=PIPE, stderr=STDOUT).communicate()[0]
            output.append(contents)
            count = len(contents)
        except IOError as e:
            if not e.errno in [errno.EPERM, errno.EACCES]:
                raise
        if count == 0:
            readable = False

    if expected is not None and expected != readable:
            raise ValueError("\n--\n".join(output))

    return readable


class MapsTests(unittest.TestCase):
    '''Test functionality of /proc/$pid/maps'''

    def setUp(self):
        '''Set up each test case'''
        self.pid_to_kill = None

    def tearDown(self):
        '''Clean up each test case'''
        if self.pid_to_kill:
            os.kill(self.pid_to_kill, 9)

    def test_00_ourself(self):
        '''Can read our own maps file'''

        # We should be able to read our own maps files.
        our_pid = os.getpid()
        self.assertTrue(maps_readable('%d' % (our_pid)), "Cannot read maps file for self (pid %d)" % (our_pid))

    def test_10_other(self):
        '''Can not read other users' processes maps file'''

        self.assertFalse(maps_readable('1'), "Should not be able to read maps file for init (pid 1)")

    def test_20_same_uid(self):
        '''Can read maps from other processes under the same uid'''

        # We should be able to read another process of the same uid's maps files.
        p = Popen(['./maps-helper-normal'], stdin=PIPE)
        self.pid_to_kill = p.pid
        self.assertTrue(maps_readable('%d' % p.pid), "Cannot read maps file for process with same uid (pid %d)" % (p.pid))

    def _check_setuid(self):
        '''Verify the required setuid program'''

        info = os.stat('maps-helper-setuid')
        self.assertEqual(info.st_uid, 0, "maps-helper-setuid not owned by root")
        self.assertEqual(info.st_mode & 0o4000, 0o4000, "maps-helper-setuid not setuid")

    def test_30_setuid_before_dropping_privs(self):
        '''Can not read setuid process before priv-dropping to our uid'''

        self._check_setuid()
        p = Popen(['./maps-helper-setuid', '/dev/stdin', 'sleep'], stdin=PIPE)
        self.pid_to_kill = p.pid
        self.assertFalse(maps_readable('%d' % p.pid, expected=False), "Can read maps file for setuid process (pid %d)" % (p.pid))

    def test_40_same_uid_but_after_setuid(self):
        '''Can not read process that priv-dropped to our uid'''

        self._check_setuid()
        p = Popen(['./maps-helper-setuid', '/dev/stdin'], stdin=PIPE)
        self.pid_to_kill = p.pid
        # pause to wait for the setuid helper to drop privs
        time.sleep(0.2)
        self.assertFalse(maps_readable('%d' % p.pid, expected=False), "Can read maps file for process with same uid (pid %d) that dropped privs" % (p.pid))

    def test_50_same_uid_but_setuid_self(self):
        '''Set-uid processes can read their own maps file'''

        self._check_setuid()
        # A priv-dropping setuid helper should be able to read its own maps files.
        self.assertTrue(maps_readable('self', command='./maps-helper-setuid'), "Setuid priv-dropper cannot read its own maps files")

if __name__ == '__main__':
    unittest.main()
