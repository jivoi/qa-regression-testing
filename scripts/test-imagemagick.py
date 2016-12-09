#!/usr/bin/python
#
#    test-imagemagick.py quality assurance test script for imagemagick
#    Copyright (C) 2008-2016 Canonical Ltd.
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
        schroot -c hardy -u root -- sh -c 'apt-get -y install file imagemagick  && ./test-imagemagick.py -v'

    TODO:
     - More utilities could be tested
     - More coders could be tested
     - Test perl interface
'''

# QRT-Depends: data imagemagick private/qrt/imagemagick.py
# QRT-Packages: file imagemagick libtiff-tools curl

import unittest, sys, os
import testlib
import shutil
import tempfile

try:
    from private.qrt.imagemagick import PrivateImagemagickTest
except ImportError:
    class PrivateImagemagickTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class ImagemagickTests(testlib.TestlibCase, PrivateImagemagickTest):
    '''Test imagemagick functionality.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="imagemagick-")
        self.current_dir = os.getcwd()

        # so temp files get cleaned up easily
        os.environ.setdefault('TMPDIR', self.tempdir)
        os.environ['TMPDIR'] = self.tempdir

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_identify(self):
        '''Test the identify utility'''

        samples = ( ('gif', 'GIF 92x84'),
                    ('jpg', 'JPEG 80x72'),
                    ('png', 'PNG 92x84'),
                    ('tiff', 'TIFF 92x84'),
                    ('xcf', 'XCF 92x84') )

        for infiletype, filedescription in samples:
            (rc, report) = testlib.cmd(["/usr/bin/identify", "./data/well-formed." + infiletype])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = 'Identify returned:\n\n %s\n\nWe expected:\n\n%s\n' % (report.rstrip(), filedescription)
            self.assertTrue(filedescription in report, result + report)


    def test_convert(self):
        '''Test convert utility'''

        conversions = ( ('gif', 'png',
                         r'PNG image( data)?, 92 x 84, 8-bit colormap, non-interlaced',
                         'GIF image data, version 89a, 92 x 84' ),

                        ('jpg', 'png',
                         r'PNG image( data)?, 80 x 72, 8-bit/color RGB, non-interlaced',
                         r'JPEG image data, JFIF standard 1.01.*' ),

                        ('png', 'gif',
                         'GIF image data, version 89a, 92 x 84',
                         r'PNG image( data)?, 92 x 84, 8-bit colormap, non-interlaced' ),

                        ('tiff', 'png',
                         r'PNG image( data)?, 92 x 84, 8-bit/color RGBA, non-interlaced',
                         r'TIFF image data, little-endian.*' ) )


        for infiletype, outfiletype, outmimetype, remimetype in conversions:
            outfilename = os.path.join(self.tempdir, infiletype + "-converted." + outfiletype)

            (rc, report) = testlib.cmd(["/usr/bin/convert",
                                        "./data/well-formed." + infiletype,
                                        outfilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            # Let's check the mime-type to make sure it generated a valid image
            self.assertFileType(outfilename, outmimetype)

            # Let's convert it back and check the mime-type again
            refilename = os.path.join(self.tempdir, infiletype + "-reconverted." + infiletype)

            (rc, report) = testlib.cmd(["/usr/bin/convert",
                                        outfilename, refilename])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            self.assertFileType(refilename, remimetype)


    def test_display(self):
        '''Test display utility'''
        failed = False
        print ""
        for f in os.listdir("./data"):
            if not f.startswith("well-formed") or not '.' in f:
                continue
            ext = f.split('.')[-1]
            if ext in ["ilbm", "emf", "wmf", "gd2", "gd", "jpc", "pbm"]:
                continue
            if ext == "gif" and (self.lsb_release['Release'] == 9.04 or \
                                 self.lsb_release['Release'] == 9.10):
                self._skipped("Skipping '%s' (broken in %s)" % (f, str(self.lsb_release['Description'])))
                print ""
                continue

            # test image
            print "  %s:" % f,
            sys.stdout.flush()
            assertshell = testlib.TimeoutFunction(self.assertShellExitEquals, 5)
            cmd = ['/usr/bin/display', os.path.join("./data", f)]
            try:
                assertshell(1, cmd)
                print "FAIL"
                failed = True
            except:
                testlib.cmd(['killall', '-9', 'display'])
                print "ok"

        self.assertFalse(failed, "Image display failed")

    def test_cve_2008_1096(self):
        '''Test for CVE-2008-1096 segfault'''

        (rc, report) = testlib.cmd(["/usr/bin/identify", "imagemagick/CVE-2008-1096.xcf"])
        search = "emory allocation failed"
        result = "Could not find '%s' in report\n" % (search)
        self.assertTrue(search in report, result + report)

        (rc, report) = testlib.cmd(["/usr/bin/convert", "imagemagick/CVE-2008-1096.xcf",
                                                        os.path.join(self.tempdir, "CVE-2008-1096.gif")])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_cve_2009_1882(self):
        '''Test for CVE-2009-1882 segfault'''
        self._skipped("TODO: test works intermittently")
        return

        bytes = 268449774
        if not testlib.cwd_has_enough_space(os.getcwd(), bytes):
            return self._skipped("Skipped: not enough space (need %dK)" % (bytes / 1024))

        fn = os.path.join(self.tempdir, 'large.tiff')
        shutil.copy('./data/well-formed.tiff', fn)

        # reset the ImageLength: tiffset -s 257 1073741840 ./large.tiff
        rc, report = testlib.cmd(['tiffset', '-s', '257', '1073741840', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # adjust the StripByteCounts: tiffset -s 279 16777217 ./large.tiff
        rc, report = testlib.cmd(['tiffset', '-s', '279', '16777217', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # adjust the StripOffsets: tiffset -s 273 16777217 ./large.tiff
        rc, report = testlib.cmd(['tiffset', '-s', '273', '16777217', fn])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # test the image (may not be long enough and may get a false negative)
        assertshell = testlib.TimeoutFunction(self.assertShellExitEquals, 60)
        cmd = ['/usr/bin/display', fn]
        try:
            assertshell(1, cmd)
        except:
            testlib.cmd(['killall', '-9', 'display'])
            self.assertEquals(0, 1, "display vulnerable")

    def test_cve_2010_4167(self):
        '''Test for CVE-2010-4167'''

        # Make sure imagemagick doesn't read config files from the current
        # directory. Example config files were obtained from here:
        # http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=601824

        bad_string = "All your base are belong to us."

        testlib.create_fill(os.path.join(self.tempdir, "coder.xml"),
'''<codermap>
  <coder magick='png' name='notpng'/>
</codermap>''')

        testlib.create_fill(os.path.join(self.tempdir, "delegates.xml"),
'''<delegatemap>
  <delegate decode='png' command="echo '%s'"/>
</delegatemap>''' % bad_string)

        shutil.copy("./data/well-formed.png", self.tempdir)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["/usr/bin/convert",
                                    "./well-formed.png",
                                    os.path.join(self.tempdir, "tempo.png")])

        result = 'Found %s in output:\n' % (bad_string)
        self.assertFalse(bad_string in report, result + report)

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_cve_2016_5118(self):
        '''Test for CVE-2016-5118'''

        outfilename = os.path.join(self.tempdir, "CVE-2016-5118")

        (rc, report) = testlib.cmd(["/usr/bin/convert",
                                    "|echo FAILED > %s" % outfilename,
                                    "null:"])

        error = "Found the %s file." % outfilename
        self.assertFalse(os.path.exists(outfilename), error)


    def test_imagetragick_1(self):
        '''Test for ImageTragick, Part 1'''

        infile = os.path.join(self.tempdir, "delete.jpg")
        outfile = os.path.join(self.tempdir, "delme")

        with open(outfile, 'w') as d:
            d.write("delme")

        with open(infile, 'w') as j:
            j.write(
"""push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'ephemeral:delme'
popgraphic-context
"""
)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["identify", infile])

        #print "%d: %s\n" % (rc, report)

        error = "Didn't find the %s file." % outfile
        self.assertTrue(os.path.exists(outfile), error)

    def test_imagetragick_2(self):
        '''Test for ImageTragick, Part 2'''

        infile = os.path.join(self.tempdir, "msl.mvg")
        outfile = os.path.join(self.tempdir, "out.png")
        xmlfile = os.path.join(self.tempdir, "msl.txt")
        hackfile = os.path.join(self.tempdir, "msl.hax")

        with open(infile, 'w') as m:
            m.write(
"""push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'msl:msl.txt'
pop graphic-context
"""
)

        with open(xmlfile, 'w') as m:
            m.write(
"""<?xml version="1.0" encoding="UTF-8"?>
<image>
<read filename="well-formed.gif" />
<write filename="msl.hax" />
</image>
"""
)

        shutil.copy("data/well-formed.gif", self.tempdir)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["convert", infile, outfile])

        #print "%d: %s\n" % (rc, report)

        error = "Found the %s file." % hackfile
        self.assertFalse(os.path.exists(hackfile), error)


    def test_imagetragick_3(self):
        '''Test for ImageTragick, Part 3'''

        infile = os.path.join(self.tempdir, "rce1.jpg")
        outfile = os.path.join(self.tempdir, "rce1")

        with open(infile, 'w') as m:
            m.write(
"""push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.0/oops.jpg"|touch "rce1)'
pop graphic-context
"""
)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["identify", infile])

        #print "%d: %s\n" % (rc, report)

        error = "Found the %s file." % outfile
        self.assertFalse(os.path.exists(outfile), error)

    def test_imagetragick_4(self):
        '''Test for ImageTragick, Part 4'''

        infile = os.path.join(self.tempdir, "rce2.jpg")
        outfile = os.path.join(self.tempdir, "rce2")

        with open(infile, 'w') as m:
            m.write(
"""push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=`wget -O- google.com > rce2`'
pop graphic-context
"""
)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["identify", infile])

        #print "%d: %s\n" % (rc, report)

        error = "Found the %s file." % outfile
        self.assertFalse(os.path.exists(outfile), error)

    def test_imagetragick_5(self):
        '''Test for ImageTragick, Part 5'''

        infile = os.path.join(self.tempdir, "read.jpg")
        outfile = os.path.join(self.tempdir, "read.png")

        with open(infile, 'w') as m:
            m.write(
"""push graphic-context
viewbox 0 0 640 480
image over 0,0 0,0 'label:@read.jpg'
popgraphic-context
"""
)

        os.chdir(self.tempdir)

        (rc, report) = testlib.cmd(["convert", infile, outfile])

        #print "%d: %s\n" % (rc, report)

        error = "Found the %s file." % outfile
        self.assertFalse(os.path.exists(outfile), error)


if __name__ == '__main__':
    # simple
    unittest.main()

    # more configurable
    #suite = unittest.TestSuite()
    #suite.addTest(unittest.TestLoader().loadTestsFromTestCase(PkgTest))
    #rc = unittest.TextTestRunner(verbosity=2).run(suite)
    #if not rc.wasSuccessful():
    #    sys.exit(1)

