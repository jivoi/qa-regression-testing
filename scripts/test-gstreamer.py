#!/usr/bin/python
#
#    test-gstreamer.py quality assurance test script for gstreamer
#    Copyright (C) 2008 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
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
  How to run in a clean virtual machine with sound enabled:
    1. apt-get -y install totem-gstreamer gstreamer0.10-plugins-good gstreamer0.10-plugins-bad \
       gstreamer0.10-plugins-bad-multiverse gstreamer0.10-plugins-ugly gstreamer0.10-ffmpeg \
       gstreamer-tools lsb-release
    5. ./test-gstreamer.py download (as non-root)
    6. ./test-gstreamer.py -v       (as non-root)

  NOTES:
    When run with the 'download' command, this file will download various files
    from http://samples.mplayerhq.hu/ if they don't already exist. These files
    should not be added to the bzr branch for qa-regression-testing due to
    copyright.

    Some files need to have the sound manually adjusted to hear them

    When running, the script will launch the executable, and you will have to
    close the application manually to proceed to the next test. It is sometimes
    best to stop the playback before closing the application (otherwise may
    occassionally get an X Window Error)

    The executables should be launched once and shutdown before running this
    script, so they can setup their config files

    For test results, and distribution particularities, see ../results/gstreamer/

'''

# QRT-Depends: data testlib_multimedia.py

import unittest, sys
import testlib
import testlib_multimedia

class TestPlayback(testlib_multimedia.MultimediaCommon):
    '''Test playback of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_multimedia.MultimediaCommon._setUp(self)
        self.exes = ['totem']

        self.files = testlib_multimedia.files

    def tearDown(self):
        '''Clean up after each test_* function'''
        pass

    def test_aac(self):
        '''Test AAC'''
        for exe in self.exes:
            self._cmd([exe], self.files, "aac")

    def test_ac3(self):
        '''Test AC3'''
        for exe in self.exes:
            self._cmd([exe], self.files, "ac3")

    def test_asf(self):
        '''Test ASF'''
        for exe in self.exes:
            self._cmd([exe], self.files, "asf")

        for exe in self.exes:
            self._cmd([exe], self.files, "asx")

        for exe in self.exes:
            self._cmd([exe], self.files, "wmv")

    def test_flv(self):
        '''Test flv'''
        for exe in self.exes:
            self._cmd([exe], self.files, "flv")

    def test_flac(self):
        '''Test flac'''
        for exe in self.exes:
            self._cmd([exe], self.files, "flac")

    def test_matroska(self):
        '''Test matroska'''
        for exe in self.exes:
            self._cmd([exe], self.files, "mkv")

    def test_mpc(self):
        '''Test mpc'''
        for exe in self.exes:
            self._cmd([exe], self.files, "mpc")

    def test_mp3(self):
        '''Test mp3'''
        for exe in self.exes:
            self._cmd([exe], self.files, "mp3")

    def test_ogg(self):
        '''Test ogg'''
        for exe in self.exes:
            self._cmd([exe], self.files, "ogg")

    def test_qt(self):
        '''Test qt'''
        for exe in self.exes:
            self._cmd([exe], self.files, "mov")

        for exe in self.exes:
            self._cmd([exe], self.files, "mp4")

        for exe in self.exes:
            self._cmd([exe], self.files, "m4v")

    def test_real(self):
        '''Test real'''
        for exe in self.exes:
            self._cmd([exe], self.files, "rm")

    def test_shn(self):
        '''Test shn'''
        for exe in self.exes:
            self._cmd([exe], self.files, "shn")

    def test_speex(self):
        '''Test speex'''
        for exe in self.exes:
            self._cmd([exe], self.files, "spx")

    def test_tta(self):
        '''Test tta'''
        for exe in self.exes:
            self._cmd([exe], self.files, "tta")

    def test_png(self):
        '''Test png'''
        # This doesn't work on dapper for some reason
        if self.release != "dapper":
            rc, report = testlib.cmd(['gst-launch', 'filesrc', 'location=./data/well-formed.png',
                                  '! decodebin ! ffmpegcolorspace ! freeze ! autovideosink'])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "download":
        testlib_multimedia.download(testlib_multimedia.files)
    else:
        unittest.main()

