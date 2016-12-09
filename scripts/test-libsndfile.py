#!/usr/bin/python
#
#    test-libsndfile.py quality assurance test script for libsndfile
#    Copyright (C) 2009-2015 Canonical Ltd.
#    Author:  Marc Deslauriers <marc.deslauriers@canonical.com>
#             Jamie Strandboge <jamie@canonical.com>
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
    In general, this test should be run in a virtual machine (VM) or possibly
    a chroot and not on a production machine. While efforts are made to make
    these tests non-destructive, there is no guarantee this script will not
    alter the machine. You have been warned.

    TODO:
    - sndfile-metadata-get
    - sndfile-metadata-set
    - sndfile-concat
    - sndfile-interleave
    - sndfile-deinterleave
'''

# QRT-Depends: data private/qrt/libsndfile.py
# QRT-Packages: lsb-release file sndfile-programs

import unittest, os
import shutil
import testlib
import tempfile

try:
    from private.qrt.libsndfile import PrivateLibsndfileTest
except ImportError:
    class PrivateLibsndfileTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"


class LibsndfileTests(testlib.TestlibCase, PrivateLibsndfileTest):
    '''Test libsndfile functionality.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libsndfile-")


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


    def test_sndfile_info(self):
        '''Test the sndfile-info utility'''

        samples = ( ('wav', '0x1 => WAVE_FORMAT_PCM'),
                    ('caf', 'Format id    : lpcm') )

        for infiletype, filedescription in samples:
            (rc, report) = testlib.cmd(["/usr/bin/sndfile-info", "./data/sound-file." + infiletype])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'sndfile-info returned:\n\n %s\n\nWe expected:\n\n%s\n' % (report.rstrip(), filedescription)
            self.assertTrue(filedescription in report, result + report)


    def test_sndfile_convert(self):
        '''Test the sndfile-convert utility'''

        # see 'sndfile-convert --help' for available formats
        conversions = ( ('aif', 'IFF data, AIFF audio'),
                        ('au', 'Sun/NeXT audio data: 16-bit linear PCM, mono, 44100 Hz'),
                        ('caf', 'CoreAudio Format audio file version 1'),
                        ('flac', 'FLAC audio bitstream data, 16 bit, mono, 44.1 kHz, 33792 samples'),
                        ('snd', 'Sun/NeXT audio data: 16-bit linear PCM, mono, 44100 Hz'),
                        ('svx', 'IFF data, 16SV 16-bit sampled sound voice'),
                        ('paf', 'data'), # mime not available
                        ('fap', 'data'), # mime not available
                        #('gsm', 'data'), # mime not available
                        ('nist', 'NIST SPHERE file'),
                        ('ircam', 'IRCAM file (MIPS little-endian)'),
                        ('sf', 'IRCAM file (MIPS little-endian)'),
                        ('voc', 'Creative Labs voice data - version 1.20'),
                        ('w64', 'Sony Wave64 RIFF data, WAVE 64 audio, mono 44100 Hz' if (self.lsb_release['Release'] >= 12.04) else 'data'), # mime not available before precise
                        #('raw', 'data'), # don't use, it is malformed
                        ('mat4', 'data'), # mime not available
                        ('mat5', 'Matlab v5 mat-file (little endian) version 0x0100'),
                        ('mat', 'data'), # mime not available
                        ('pvf', 'portable voice format (binary 1 44100 16)'),
                        #('sds', '\\012- SysEx File -'),
                        #('sd2', 'MPEG ADTS, layer II, v1, Monaural'), # 'output file format is invalid (0x00010051)' error
                        #('vox', 'data'), # 'output file format is invalid (0x00010021)' error
                        #('xi', 'Fast Tracker II Instrument'), # 'output file format is invalid (0x00010051)' error
                      )

        print ""
        for outfiletype, outmimetype in conversions:
            print "  %s:" % outfiletype,
            outfilename = "converted." + outfiletype

            (rc, report) = testlib.cmd(["/usr/bin/sndfile-convert",
                                        "./data/sound-file.wav",
                                        os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid sound file
            self._check_mime_type(outfilename, outmimetype)

            # Let's convert it back and check the mime-type again
            refilename = outfiletype + "-reconverted.wav"

            (rc, report) = testlib.cmd(["/usr/bin/sndfile-convert",
                                        os.path.join(self.tempdir, outfilename),
                                        os.path.join(self.tempdir, refilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self._check_mime_type(refilename, "RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz")

            print "pass"

        # try fake sound file
        ext = "nonexistent"
        print "  %s (expected failure):" % ext,
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-convert",
                                        "-%s" % ext,
                                        "./data/sound-file.wav",
                                        os.path.join(self.tempdir, "fake.%s" % ext)])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        print "pass"


    def test_paf(self):
        '''Test paf'''
        print ""
        print "  convert:",
        infile = "./data/sound-file.wav"
        outfile = os.path.join(self.tempdir, "sound-file.paf")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-convert",
                                    infile, outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        print "pass"

        print "  info:",
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-info", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["Signature   : ' paf'",
                       "Sample Rate : 44100",
                       "Channels    : 1",
                       "Format      : 0 => 16 bit linear PCM",
                       "Format      : 0x20050002"]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)
        print "pass"

        print "  spectrogram:",
        pngfile = os.path.join(self.tempdir, "sound-file.png")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-spectrogram",
                                    outfile, "800", "600", pngfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/file", "-b", pngfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["PNG image",
                       "800 x 600",
                       "8-bit/color RGB",
                       "non-interlaced",
                      ]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)
        print "pass"

        print "  convert dual-channel:",
        infile = "./data/iamed1906.flac"
        outfile = os.path.join(self.tempdir, "iamed1906.paf")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-convert",
                                    infile, outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/sndfile-info", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["Signature   : ' paf'",
                       "Channels    : 2",
                       "Format      : 0x20050002"]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)
        print "pass"

        print "  mono:",
        infile = outfile
        outfile = os.path.join(self.tempdir, "mono.paf")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-mix-to-mono",
                                    infile, outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/sndfile-info", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["Signature   : ' paf'",
                       "Channels    : 1",
                       "Format      : 0x20050002"]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)
        print "pass"

        print "  cmp:",
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-cmp",
                                    infile, outfile])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'Number of channels of files'
        result = "Could not find '%s' in report:\n%s" % (search, report)
        self.assertTrue(search in report, result)

        samefile = os.path.join(self.tempdir, "same.paf")
        shutil.copy(infile, samefile)

        (rc, report) = testlib.cmd(["/usr/bin/sndfile-cmp",
                                    infile, samefile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        print "pass"

    def test_spectrogram(self):
        '''Test sndfile-spectrogram'''
        infile = "./data/sound-file.wav"
        outfile = os.path.join(self.tempdir, "sound-file.png")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-spectrogram",
                                    infile, "800", "600", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/file", "-b", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["PNG image",
                       "800 x 600",
                       "8-bit/color RGB",
                       "non-interlaced",
                      ]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)

    def test_mix_to_mono(self):
        '''Test sndfile-mix-to-mono'''
        infile = "./data/iamed1906.flac"
        outfile = os.path.join(self.tempdir, "mono.flac")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-mix-to-mono",
                                    infile, outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/sndfile-info", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["FLAC Stream Metadata",
                       "Sample Rate : 11025",
                       "Channels    : 1",
                       "Format      : 0x00170002"]:

            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)

    def test_generate_chirp(self):
        '''Test sndfile-generate-chirp'''
        outfile = os.path.join(self.tempdir, "chirp.wav")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-generate-chirp",
                                    "44100", "1", outfile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        for search in ["Start frequency :", "End   frequency :"]:
            result = "Could not find '%s' in report:\n%s" % (search, report)
            self.assertTrue(search in report, result)

        self._check_mime_type(outfile, "RIFF (little-endian) data, WAVE audio, mono 44100 Hz")

        # expected failure
        outfile = os.path.join(self.tempdir, "chirp.noexistent")
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-generate-chirp",
                                    "44100", "1", outfile])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'Error : Can only generate files with extentions'
        result = "Could not find '%s' in report:\n%s" % (search, report)
        self.assertTrue(search in report, result)

    def test_cmp(self):
        '''Test sndfile-cmp'''
        origfile = "./data/sound-file.wav"
        samefile = os.path.join(self.tempdir, "same.wav")
        shutil.copy(origfile, samefile)

        (rc, report) = testlib.cmd(["/usr/bin/sndfile-cmp",
                                    origfile, samefile])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        notsamefile = "./data/iamed1906.flac"
        (rc, report) = testlib.cmd(["/usr/bin/sndfile-cmp",
                                    origfile, notsamefile])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
        search = 'Samplerates of files'
        result = "Could not find '%s' in report:\n%s" % (search, report)
        self.assertTrue(search in report, result)


if __name__ == '__main__':
    unittest.main()

