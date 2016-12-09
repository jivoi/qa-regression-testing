#!/usr/bin/python
#
#    test-audiofile.py quality assurance test script for audiofile
#    Copyright (C) 2015 Canonical Ltd.
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
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
# QRT-Packages: file audiofile-tools
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: data

'''
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

'''


import os
import subprocess
import sys
import unittest
import testlib
import tempfile

try:
    from private.qrt.Audiofile import PrivateAudiofileTest
except ImportError:
    class PrivateAudiofileTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class AudiofileTest(testlib.TestlibCase, PrivateAudiofileTest):
    '''Test Audiofile.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="audiofile-")

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


    def test_sfinfo(self):
        '''Test the sfinfo utility'''

        filedescription = 'Microsoft RIFF WAVE Format (wave)'
        (rc, report) = testlib.cmd(["/usr/bin/sfinfo", "./data/sound-file.wav"])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = 'sfinfo returned:\n\n %s\n\nWe expected:\n\n%s\n' % (report.rstrip(), filedescription)
        self.assertTrue(filedescription in report, result + report)


    def test_sfconvert(self):
        '''Test the sfconvert utility'''

        conversions = ( ('aiff', 'IFF data, AIFF audio'),
                        ('aifc', 'IFF data, AIFF-C compressed audio'),
                        ('next', 'Sun/NeXT audio data: 16-bit linear PCM, mono, 44100 Hz'),
                        ('wave', 'RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz'),
                        ('bics', 'IRCAM file (VAX little-endian)'),
                        ('voc', 'Creative Labs voice data - version 1.20'),
                        ('nist', 'NIST SPHERE file'),
                        ('caf', 'CoreAudio Format audio file version 1'),
                      )

        print ""
        for outfiletype, outmimetype in conversions:
            print "  %s:" % outfiletype,
            outfilename = "converted." + outfiletype

            (rc, report) = testlib.cmd(["/usr/bin/sfconvert",
                                        "./data/sound-file.wav",
                                        os.path.join(self.tempdir, outfilename),
                                        "format", outfiletype])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid sound file
            self._check_mime_type(outfilename, outmimetype)

            # Let's convert it back and check the mime-type again
            refilename = outfiletype + "-reconverted.wav"

            (rc, report) = testlib.cmd(["/usr/bin/sfconvert",
                                        os.path.join(self.tempdir, outfilename),
                                        os.path.join(self.tempdir, refilename),
                                        "format", "wave"])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._check_mime_type(refilename, "RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz")

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
