#!/usr/bin/python
#
#    test-libvorbis.py quality assurance test script for libvorbis
#    Copyright (C) 2008-2012 Canonical Ltd.
#    Author:  Marc Deslauriers <marc.deslauriers@canonical.com>
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file vorbis-tools  && ./test-libvorbis.py -v'

    TODO:
     - Add some more ogg files with different encodings, etc.
'''

# QRT-Depends: data libvorbis
# QRT-Packages: file vorbis-tools

import unittest, os
import testlib
import tempfile

class LibvorbisTests(testlib.TestlibCase):
    '''Test libvorbis functionality.'''


    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="libvorbis-")


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

        result = 'Mime type from file: %s, expected: %s\n' % (report, mimetype)
        self.assertEquals(report.rstrip(), mimetype, result)


    def test_information(self):
        '''Test parsing ogg file information'''

        samples = ( ('patas_de_trapo.oga', 'Total data length: 1006561 bytes'),
                    ('Edison_Phonograph_1.ogg', 'Total data length: 796285 bytes') )

        for filename, length in samples:
            (rc, report) = testlib.cmd(["/usr/bin/ogginfo", "./data/" + filename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'Ogginfo returned:\n\n %s\n\nWe expected:\n\n%s\n' % (report.rstrip(), length)
            self.assertTrue(length in report, result + report)


    def test_convert(self):
        '''Test decoding and encoding'''

        conversions = ( ('patas_de_trapo.oga', 'patas_de_trapo.wav',
                         'RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, stereo 44100 Hz'),

                        ('Edison_Phonograph_1.ogg', 'Edison_Phonograph_1.wav',
                         'RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 22050 Hz') )

        for infilename, outfilename, outmimetype in conversions:

            (rc, report) = testlib.cmd(["/usr/bin/oggdec", 
                                        "./data/" + infilename,
                                        "-o", os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid .wav file
            self._check_mime_type(outfilename, outmimetype)

            # Let's convert it back and see if it's a valid vorbis file
            (rc, report) = testlib.cmd(["/usr/bin/oggenc",
                                        os.path.join(self.tempdir, outfilename),
                                         "-o", os.path.join(self.tempdir, infilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            (rc, report) = testlib.cmd(["/usr/bin/ogginfo", os.path.join(self.tempdir, infilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)


    def test_cve_2008_1419_1420_1423(self):
        '''Test for CVE-2008-1419,1420,1423'''

        testfiles   = [ '014.ogg',            # fp-exception on i386
                        'maptype2.ogg',       # segfault
                        '002.ogg']           # segfault

        # This causes maverick to go into a loop
        if self.lsb_release['Release'] != 10.10:
            testfiles.append('011.ogg')

        # It appears the patch for https://trac.xiph.org/changeset/14811 now
        # causes 011.ogg to crash with a Floating point exception, *sigh*

        for filename in testfiles:

            outfilename = filename + "-converted.wav"

            (rc, report) = testlib.cmd(["/usr/bin/oggdec", 
                                        "libvorbis/" + filename,
                                        "-o", os.path.join(self.tempdir, outfilename)])
            result = 'Got exit code %d, expected 0, 1, or -8\n' % rc
            self.assertTrue(rc == 0 or rc == 1 or rc == -8, result + report)

    def test_cve_2009_2663(self):
        '''Test for CVE-2009-2663'''

        testfiles   = ( ('video-1frag.ogg.13.ogg'),
                        ('video-1frag.ogg.14.ogg'),
                        ('video-1frag.ogg.15.ogg'),
                        ('video-1frag.ogg.16.ogg'),
                        ('video-1frag.ogg.17.ogg'),
                        ('video-1frag.ogg.18.ogg'),
                        ('video-1frag.ogg.19.ogg'),
                        ('video-1frag.ogg.20.ogg'),
                        ('video-1frag.ogg.25.ogg'),
                        ('video-1frag.ogg.26.ogg'),
                        ('video-1frag.ogg.27.ogg'),
                        ('video-1frag.ogg.28.ogg'),
                        ('video-1frag.ogg.29.ogg'),
                        ('video-1frag.ogg.30.ogg'),
                        ('video-1frag.ogg.31.ogg'),
                        ('video-1frag.ogg.32.ogg'),
                        ('video-1frag.ogg.38.ogg'),
                        ('video-1frag.ogg.39.ogg'),
                        ('video-1frag.ogg.40.ogg'),
                        ('video-1frag.ogg.41.ogg'),
                        ('video-1frag.ogg.42.ogg'),
                        ('video-1frag.ogg.43.ogg'),
                        ('video-1frag.ogg.44.ogg'),
                        ('video-1frag.ogg.45.ogg'),
                        ('video-1frag.ogg.48.ogg') )

        for filename in testfiles:

            outfilename = filename + "-converted.wav"

            (rc, report) = testlib.cmd(["/usr/bin/oggdec", 
                                        "libvorbis/cve-2009-2663/" + filename,
                                        "-o", os.path.join(self.tempdir, outfilename)])
            expected = 1
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

    def test_cve_2008_1420_regression(self):
        '''Test for CVE-2008-1420 regression'''

        outfilename = "regression-converted.wav"

        (rc, report) = testlib.cmd(["/usr/bin/oggdec", 
                                    "libvorbis/lits-vorbis1.0b1.ogg",
                                    "-o", os.path.join(self.tempdir, outfilename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)
            

if __name__ == '__main__':
    unittest.main()

