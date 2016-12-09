#!/usr/bin/python
#
#    test-libav.py quality assurance test script for libav
#    Copyright (C) 2010-2014 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: libav-tools
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data private/qrt/libav.py

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    How to run in a clean VM:
    $ ./make-test-tarball test-libav.py     # creates tarball in /tmp/
    $ scp /tmp/qrt-test-libav.tar.gz root@vm.host:/tmp
    on VM:
    # cd /tmp ; tar zxvf ./qrt-test-libav.tar.gz
    # cd /tmp/qrt-test-libav ; ./install-packages ./test-libav.py
    # ./test-libav.py -v

    To run in all VMs named sec*:
    $ vm-qrt -p sec test-libav.py

'''


import unittest, sys, os, tempfile
import testlib

try:
    from private.qrt.libav import PrivateLibavTest
except ImportError:
    class PrivateLibavTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class LibavTest(testlib.TestlibCase, PrivateLibavTest):
    '''Test libav.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libav-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _check_mime_type(self, filename, mimetype):
        '''Checks the mime type of the file specified'''

        (rc, report) = testlib.cmd(["/usr/bin/file", "-b", os.path.join(self.tempdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = 'Mime type from \'%s\': %s, expected: %s\n' % (filename, report, mimetype)
        self.assertEquals(report.rstrip(), mimetype, result)

    def test_libav_encoding(self):
        '''Test ffmpeg by encoding some files'''

        if self.lsb_release['Release'] >= 14.04:
            mkv_type = 'Matroska data'
        else:
            mkv_type = 'EBML file, creator matroska'


        # TODO: see 'avconv -formats' to figure out more formats
        conversions = [ ('aiff',  'IFF data, AIFF audio'),
                        ('au',    'Sun/NeXT audio data: 16-bit linear PCM, mono, 44100 Hz'),
                        ('voc',   'Creative Labs voice data - version 1.20'),
                        ('mkv',    mkv_type),
                        ('webm',  'WebM'),
                        ('flac',  'FLAC audio bitstream data, 16 bit, mono, 44.1 kHz, 33792 samples'),
                        ('ogg',   'Ogg data, FLAC audio')
                      ]

        print ""
        for outfiletype, outmimetype in conversions:
            print "  %s:" % outfiletype,

            # Can't decode its own flac files on 14.04, how awesome.
            if self.lsb_release['Release'] == 14.04:
                if outfiletype == 'flac':
                    print "skipped"
                    continue

            outfilename = "converted." + outfiletype

            (rc, report) = testlib.cmd(["/usr/bin/avconv", "-i",
                                        "./data/sound-file.wav",
                                        os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid sound file
            self._check_mime_type(outfilename, outmimetype)

            # Let's convert it back and check the mime-type again
            refilename = outfiletype + "-reconverted.wav"

            (rc, report) = testlib.cmd(["/usr/bin/avconv", "-i",
                                        os.path.join(self.tempdir, outfilename),
                                        os.path.join(self.tempdir, refilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            if refilename == "voc-reconverted.wav":
                self._check_mime_type(refilename, "RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 45454 Hz")
            else:
                self._check_mime_type(refilename, "RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz")

            print "pass"

    def test_libav_decoding(self):
        '''Test libav by decoding some files'''

        # TODO: see 'avconv -formats' to figure out more formats
        conversions = ( ('Edison_Phonograph_1.ogg',   'RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 22050 Hz'),
                        ('iamed1906_64kb.mp3',  'RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 11025 Hz'),
                        ('patas_de_trapo.oga',  'RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz'),
                      )

        print ""
        for infile, outmimetype in conversions:
            print "  %s:" % infile,
            outfilename = infile + "outfilename.wav"

            (rc, report) = testlib.cmd(["/usr/bin/avconv", "-i",
                                        os.path.join("./data/", infile),
                                        os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid sound file
            self._check_mime_type(outfilename, outmimetype)

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
