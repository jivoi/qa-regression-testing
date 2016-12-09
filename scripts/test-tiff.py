#!/usr/bin/python
#
#    test-tiff.py quality assurance test script for tiff
#    Copyright (C) 2009-2016 Canonical Ltd.
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
#
# packages required for test to run:
# QRT-Packages: libtiff-tools file imagemagick valgrind
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: tiff data private/qrt/tiff.py

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release file libtiff-tools imagemagick && ./test-tiff.py -v'
'''


import unittest, subprocess, sys, tempfile, os
import testlib

try:
    from private.qrt.tiff import PrivateTiffTest
except ImportError:
    class PrivateTiffTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class TiffTest(testlib.TestlibCase, PrivateTiffTest):
    '''Test tiff.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="tiff-")
        self.topdir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.topdir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _check_mime_type(self, filename, mimetype):
        '''Checks the mime type of the file specified'''

        cmd = ["/usr/bin/file", "-b", os.path.join(self.tempdir, filename)]
        (rc, report) = testlib.cmd(cmd)
        expected = 0
        result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, " ".join(cmd))
        self.assertEquals(expected, rc, result + report)

        result = 'Mime type from file: %s, expected: %s\n' % (report, mimetype)
        self.assertEquals(report.rstrip(), mimetype, result)

    def _tiffinfo_check(self, filename, badformat=0, dump=0, tempdir=1, expected=0):
        '''Checks if the file specified can be parsed with tiffinfo'''

        command = ["/usr/bin/tiffinfo"]
        if dump:
            command.extend(["-d"])
        if tempdir:
            command.extend([os.path.join(self.tempdir, filename)])
        else:
            command.extend([filename])

        #print "running command: '%s'" % command

        (rc, report) = testlib.cmd(command)
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, dump and result or result + report)

        checks = ( 'TIFF Directory at', 'Image Width', 'Compression Scheme' )
        if not badformat:
            for check in checks:
                result = "Couldn't find '%s' in report: %s\n" % (check, report)
                self.assertTrue(check in report, result)

    def test_2tiff(self):
        '''Test *2tiff utilities'''

        # For some reason, it won't read our sample gif...
        samples = ( 'bmp', 'ppm' )

        for filetype in samples:
            outfilename = 'out.' + filetype

            (rc, report) = testlib.cmd(["/usr/bin/" + filetype + "2tiff",
                                        "./data/well-formed." + filetype,
                                        os.path.join(self.tempdir, outfilename)])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's see if it generated a valid tiff image
            self._tiffinfo_check(outfilename)

    def _jpg_convert(self, filename):
        '''Convert to jpg to check for conversion warnings'''
        jpg_tmp = tempfile.NamedTemporaryFile(prefix='convert-',suffix='.jpg')
        jpg_filename = jpg_tmp.name

        # Try a to-JPG conversion to catch anything else
        self.assertShellOutputEquals("",
                                     ["/usr/bin/convert", filename,
                                      os.path.join(self.tempdir, jpg_filename)],
                                     expected=0)

    def _validate_tiff_image(self, filename, expected=0, info=None, badformat=None, skip_conversion=False):
        ycbcr_tmp = tempfile.NamedTemporaryFile(prefix='ycbcr-',suffix='.tiff')
        rgba_tmp = tempfile.NamedTemporaryFile(prefix='rgba-',suffix='.tiff')
        ycbcr_filename = ycbcr_tmp.name
        rgba_filename = rgba_tmp.name

        if info == None:
            info = expected
        if badformat == None:
            badformat = info

        # Check TIFF
        self.assertShellExitEquals(info,["/usr/bin/tiffinfo", filename])

        # Do a raw RGB conversion
        self.assertShellExitEquals(expected,["/usr/bin/tiff2rgba",
                                   filename, rgba_filename])

        if skip_conversion:
            return

        # Convert it to ycbcr first
        self.assertShellExitEquals(expected,["/usr/bin/rgb2ycbcr",
                                   filename,
                                   os.path.join(self.tempdir, ycbcr_filename)])

        # Only attempt re-conversion of valid TIFFs
        if (expected != 0):
            return

        # Let's see if it generated a valid tiff image
        self._tiffinfo_check(ycbcr_filename, badformat)

        # Now convert it back to rgba
        self.assertShellExitEquals(0,["/usr/bin/tiff2rgba",
                                   os.path.join(self.tempdir, ycbcr_filename),
                                   os.path.join(self.tempdir, rgba_filename)])

        # Let's see if it generated a valid tiff image
        self._tiffinfo_check(rgba_filename, badformat)

    def test_rgb2ycbcr_tiff2rgba(self):
        '''Test rgb2ycbcr and tiff2rgba utilities'''

        self._validate_tiff_image("./data/well-formed.tiff")

    def test_tiff2(self):
        '''Test tiff2* utilities'''

        ps_mime_type = 'PostScript document text conforming DSC level 3.0, type EPS, Level 1'
        if self.lsb_release['Release'] <= 8.04:
            ps_mime_type = 'PostScript document text conforming at level 3.0 - type EPS'

        if self.lsb_release['Release'] < 15.04:
            conversions = ( ('pdf', 'PDF document, version 1.1', '-o'),
                            ('ps', ps_mime_type, '-O'),
                            ('rgba', 'TIFF image data, little-endian', '') )
        elif self.lsb_release['Release'] < 15.10:
            conversions = ( ('pdf', 'PDF document, version 1.1', '-o'),
                            ('ps', ps_mime_type, '-O'),
                            ('rgba', 'TIFF image data, little-endian, direntries=18, height=84, bps=19374, compression=PackBits (Macintosh RLE), PhotometricIntepretation=RGB, name=/home/kees/laughing_kees-drop.tiff, width=92', '') )
        else:
            conversions = ( ('pdf', 'PDF document, version 1.1', '-o'),
                            ('ps', ps_mime_type, '-O'),
                            ('rgba', 'TIFF image data, little-endian, direntries=18, height=84, bps=19374, compression=PackBits (Macintosh RLE), PhotometricIntepretation=RGB, name=/home/kees/laughing_kees-drop.tiff, orientation=upper-left, width=92', '') )

        for outfiletype, outmimetype, option in conversions:
            outfilename = "converted." + outfiletype

            cmd = ["/usr/bin/tiff2" + outfiletype,
                   "./data/well-formed.tiff", option,
                   os.path.join(self.tempdir, outfilename)]

            (rc, report) = testlib.cmd(cmd)
            expected = 0
            result = 'Got exit code %d, expected %d (%s)\n' % (rc, expected, " ".join(cmd))
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid image
            self._check_mime_type(outfilename, outmimetype)


    def test_lp380149(self):
        '''LP: #380149 via PostScript comparison'''
        self.assertShellExitEquals(0, ['tiff2ps', 'tiff/lp380149.tiff'], stdout=file('/dev/null'), stderr=subprocess.PIPE)

        # The following test doesn't work on Oneiric+ as the resulting file
        # isn't quite identical, so skip for now
        if self.lsb_release['Release'] >= 11.10:
            return

        ps = tempfile.NamedTemporaryFile(prefix = 'tiff2ps-test-', suffix='.ps')
        self.assertShellExitEquals(0, ['tiff2ps', 'tiff/good.tiff'], stdout=ps, stderr=subprocess.PIPE)
        ps.flush()
        ps.seek(0)
        # Filter out CreationDate
        ps_test = "\n".join([x for x in ps.read().splitlines() if not x.startswith('%%CreationDate:')])+"\n"
        ps_good = file('tiff/good.ps').read()
        #file('/tmp/wtf.ps','w').write(ps_test)
        #subprocess.call(['diff','-u','tiff/good.ps','/tmp/wtf.ps'])
        self.assertTrue(ps_test == ps_good, "PS output differs")

    def test_lp589145(self):
        '''LP: #589145 crash'''
        self._validate_tiff_image("tiff/lp589145.tif", badformat=1)

    def test_lp589565(self):
        '''LP: #589565 crash'''

        if self.lsb_release['Release'] >= 12.10:
            info = 1
        else:
            info = 0

        self._validate_tiff_image("tiff/lp589565.tif", info=info)

    def test_lp591605(self):
        '''LP: #591605 OOB Read'''

        if self.lsb_release['Release'] == 11.10 or \
           self.lsb_release['Release'] == 12.04:
            expected_rc = 0
            skip_conversion = True
        else:
            expected_rc = 1
            skip_conversion = False

        self._validate_tiff_image("tiff/lp591605.tif", expected=expected_rc,
                                  info=0, skip_conversion=skip_conversion)

    def test_lp731540(self):
        '''LP: #731540 regression in CCITTFAX4'''
        self._validate_tiff_image("tiff/lp731540.tif")
        self._jpg_convert("tiff/lp731540.tif")

    def test_multifile(self):
        '''RH BZ 552360 multifile regression'''
        self._validate_tiff_image("tiff/rh-bz552360.tif")

    def test_lp1439186(self):
        '''LP: #1439186 predictor tag regression'''

        self._tiffinfo_check("./tiff/lp1439186/small.tiff", tempdir=False)

        outfilename = os.path.join(self.tempdir, "small-c2.tiff")

        (rc, report) = testlib.cmd(["/usr/bin/tiffcp", "-c", "lzw:2",
                                    "./tiff/lp1439186/small.tiff",
                                    outfilename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        self._tiffinfo_check(outfilename, tempdir=False)

        (rc, report) = testlib.cmd(["/usr/bin/tiffinfo",
                                    outfilename])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        search = 'Predictor: horizontal differencing 2 (0x2)'
        self.assertTrue(search in report,
                        "Couldn't find Predictor in %s" % report)


if __name__ == '__main__':
    # simple
    unittest.main()
