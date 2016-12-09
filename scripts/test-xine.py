#!/usr/bin/python
#
#    test-xine.py quality assurance test script for Xine
#    Copyright (C) 2008 Canonical Ltd.
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

'''
  How to run in a clean virtual machine with sound enabled:
    1. apt-get -y install totem-xine xine-ui
    2. apt-get -y install amarok-xine (Hardy and below)
    3. apt-get -y install amarok (Intrepid and above)
    4. apt-get -y install libxine-extracodecs (dapper only)
    5. ./test-xine.py download (as non-root)
    6. ./test-xine.py -v       (as non-root)

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

    amarok is audio only, but will play the files

    The executables should be launched once and shutdown before running this
    script, so they can setup their config files

    To speed up the process, the following amarok options should be turned off:
    - General/Show tray icon
    - Playback/No fadeout
    - Playback/Fade out on exit

    It takes a while for amarok to shutdown, but should eventually. If not, do
    'killall amarokapp ; killall kio_file'

    May need the packages from packages.medibuntu.com (see
    https://help.ubuntu.com/community/Medibuntu), but the existing packages
    should work ok

    For test results, and distribution particularities, see ../results/xine.

'''

# QRT-Depends: testlib_multimedia.py

import unittest, sys
import testlib_multimedia

class TestPlayback(testlib_multimedia.MultimediaCommon):
    '''Test playback of various files'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_multimedia.MultimediaCommon._setUp(self)
        #self.exes = ['amarok-xine', 'gxine', 'oxine', 'totem-xine', 'xine-ui']
        if self.release >= "intrepid":
            self.exes = ['amarok','totem-xine','xine']
        # In a hardy vm, xine-ui crashes X
        elif self.release == "hardy":
            self.exes = ['amarok','totem-xine']
        else:
            self.exes = ['amarok','totem','xine']

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

    def test_film(self):
        '''Test film'''
        for exe in self.exes:
            self._cmd([exe], self.files, "film")

        for exe in self.exes:
            self._cmd([exe], self.files, "CAK")

        for exe in self.exes:
            self._cmd([exe], self.files, "cpk")

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

    def test_wc3movie(self):
        '''Test wc3movie'''
        if self.release != "hardy":
            for exe in self.exes:
                self._cmd([exe], self.files, "mve")

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


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "download":
        testlib_multimedia.download(testlib_multimedia.files)
    else:
        unittest.main()

