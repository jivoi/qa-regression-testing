#!/usr/bin/python
#
#    test-libvpx.py quality assurance test script for libvpx
#    Copyright (C) 2010 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Portions based on test-ffmpeg.py by:
#      Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: ffmpeg totem gstreamer0.10-plugins-bad chromium-browser
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data libvpx testlib_multimedia.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ sudo apt-get -y install <QRT-Packages> && sudo ./test-libvpx.py -v'

    How to run in a clean schroot named 'maverick':
    $ schroot -c maverick -u root -- sh -c 'apt-get -y install <QRT-Packages> && ./test-libvpx.py -v'
'''


import unittest, subprocess, sys, os, tempfile
import glob
import testlib
import testlib_multimedia

try:
    from private.qrt.libvpx import PrivateLibvpxTest
except ImportError:
    class PrivateLibvpxTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibvpxTest(testlib_multimedia.MultimediaCommon, PrivateLibvpxTest):
    '''Test libvpx'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        testlib_multimedia.MultimediaCommon._setUp(self)
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libvpx-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _check_strings_output(self, filename, strings):
        '''Check the output of 'strings' command'''

        (rc, report) = testlib.cmd(["strings", os.path.join(self.tempdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # TODO: do one pass
        for s in strings:
            found = False
            for line in report.splitlines():
                if line.startswith(s):
                    found = True
                    break

            result = "Could not find '%s' in output" % (s)
            if not found:
                print filename
                subprocess.call(['bash'])
            self.assertTrue(found, result)

    def _test_libvpx_encoding(self):
        '''Test libvpx by encoding a webm sound file to different formats'''
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("Skipped (not available on Ubuntu < 10.10)")

        conversions = [ ('aiff',  'IFF data, AIFF audio'),
                        ('au',    'Sun/NeXT audio data: 16-bit linear PCM, mono, 44100 Hz'),
                        ('voc',   'Creative Labs voice data - version 1.20'),
                        ('flac',  'FLAC audio bitstream data, 16 bit, mono, 44.1 kHz, 34752 samples'),
                        ('ac3',   'ATSC A/52 aka AC-3 aka Dolby Digital stream, 44.1 kHz,, complete main (CM) 1 front/0 rear, LFE off,, 64 kbit/s reserved Dolby Surround mode'),
                        ('ogg',   'Ogg data, FLAC audio'),
                      ]

        print ""
        for outfiletype, outmimetype in conversions:
            print "  %s:" % outfiletype,
            outfilename = os.path.join(self.tempdir, "converted." + outfiletype)

            (rc, report) = testlib.cmd(["/usr/bin/ffmpeg", "-i",
                                        "./data/sound-file.webm",
                                        outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid sound file
            self.assertFileType(outfilename, outmimetype)

            # Let's convert it back and check the mime-type again
            refilename = os.path.join(self.tempdir, outfiletype + "-reconverted.webm")

            (rc, report) = testlib.cmd(["/usr/bin/ffmpeg", "-i",
                                        outfilename, refilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(refilename, "data")
            self._check_strings_output(refilename, ['webm', 'A_VORBIS'])

            print "pass"

    def test_libvpx_decoding(self):
        '''Test libvpx by decoding some files to a webm file'''
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("Skipped (not available on Ubuntu < 10.10)")
        elif self.lsb_release['Release'] >= 12.04:
            filetype = 'WebM'
        else:
            filetype = 'data'

        conversions = ( ('Edison_Phonograph_1.ogg', filetype),
                        ('iamed1906_64kb.mp3',      filetype),
                        ('patas_de_trapo.oga',      filetype),
                        ('rfbproxy-jaunty.mpg',     filetype),
                      )

        print ""
        for infile, outmimetype in conversions:
            print "  %s:" % infile,
            outfilename = os.path.join(self.tempdir, infile + "outfilename.webm")

            (rc, report) = testlib.cmd(["/usr/bin/ffmpeg", "-i",
                                        os.path.join("./data/", infile),
                                        outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid file
            self.assertFileType(outfilename, outmimetype)

            strings = ['webm']
            ext = os.path.splitext(infile)[1]
            if ext in ['.mpg']: # video files
                strings.append('V_VP8')
            else:              # audio files
                strings.append('A_VORBIS')
            self._check_strings_output(outfilename, strings)

            print "pass"

    def test_webm_movie(self):
        '''Test webm movie (audio and video)'''
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("Skipped (not available on Ubuntu < 10.10)")

        print ""

        filename = "./libvpx/elephants-dream.webm"
        outfilename = os.path.join(self.tempdir, os.path.basename(filename) + "outfilename.mp4")

        print "  %s to %s:" % (os.path.splitext(filename)[1], os.path.splitext(outfilename)[1]),
        sys.stdout.flush()
        (rc, report) = testlib.cmd(["/usr/bin/ffmpeg", "-i",
                                    filename, outfilename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        self.assertFileType(outfilename, 'ISO Media, MPEG v4 system, version 1')
        print "pass"

        # Let's convert it back and check the mime-type again
        refilename = os.path.join(self.tempdir, "mp4" + "-reconverted.webm")
        print "  %s to %s:" % (os.path.splitext(outfilename)[1], os.path.splitext(refilename)[1]),
        sys.stdout.flush()
        (rc, report) = testlib.cmd(["/usr/bin/ffmpeg", "-i",
                                    outfilename, refilename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        if self.lsb_release['Release'] >= 12.04:
            self.assertFileType(refilename, "WebM")
        else:
            self.assertFileType(refilename, "data")
        self._check_strings_output(refilename, ['webm', 'V_VP8', 'A_VORBIS'])
        print "pass"

        for f in [filename, os.path.join(self.tempdir, outfilename), os.path.join(self.tempdir, refilename)]:
            seconds = 125
            print "  playback %s (%d seconds):" % (os.path.basename(f), seconds),
            sys.stdout.flush()
            self._player_cmd("ffplay", f, seconds)
            print "pass"

    def test_play_webm(self):
        '''Test webm playback'''
        if self.lsb_release['Release'] < 10.10:
            return self._skipped("Skipped (not available on Ubuntu < 10.10)")

        expected = 0
        print ""
        for f in glob.glob('./data/*webm'):
            seconds = 5
            if "rfbproxy" in f:
                seconds = 15
            print "  %s (%d secs):" % (os.path.basename(f), seconds),
            sys.stdout.flush()
            self._player_cmd("totem", f, seconds)
            print "pass"

    def test_play_webm_in_chromium(self):
        '''Test webm playback in chromium'''
        expected = 0
        print ""
        for f in glob.glob('./data/*webm'):
            seconds = 5
            if "rfbproxy" in f:
                seconds = 15
            print "  %s (%d secs):" % (os.path.basename(f), seconds),
            sys.stdout.flush()
            self._player_cmd("chromium-browser", f, seconds)
            print "pass"

        f = "./libvpx/elephants-dream.html"
        seconds = 125
        print "  %s (%d secs):" % (os.path.basename(f), seconds),
        sys.stdout.flush()
        self._player_cmd("chromium-browser", f, seconds)
        print "pass"


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)
