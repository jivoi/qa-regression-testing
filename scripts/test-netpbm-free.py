#!/usr/bin/python
#
#    test-netpbm-free.py quality assurance test script for netpbm-free
#    Copyright (C) 2008-2010 Canonical Ltd.
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
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install file netpbm  && ./test-netpbm-free.py -v'

    TODO:
     There are more utilities in netpbm-free that should be tested.
'''

# QRT-Depends: data netpbm-free
# QRT-Packages: netpbm

import unittest, os
import re
import shutil
import testlib
import tempfile

class NetpbmTests(testlib.TestlibCase):
    '''Test netpbm-free functionality.'''


    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="netpbm-")


    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)


    def _write_file(self, filename, data):
        '''Writes out a file into the temporary directory'''

        f = open(os.path.join(self.tempdir, filename), 'w')
        f.write(data)
        f.close()


    def _ppmquant_file(self, infile, outfile, q):
        '''Writes out a file into the temporary directory'''
        (rc, report) = testlib.cmd(["/usr/bin/ppmquant", "-quiet", q, infile])
        expected = 0
        result = 'Got exit code %d, expected %d for \'ppquant %s %s\'\n' % (rc, expected, q, infile)
        self.assertEquals(expected, rc, result + report)
        self._write_file(outfile, report)
        self._check_mime_type(outfile, "ppm")


    def _check_mime_type(self, filename, filetype):
        '''Checks the mime type of the file specified'''

	# fuzzy is useful when 'file' outputs the file dimensions. pbm is
	# listed cause sometimes it is 'raw text' and sometimes 'raw data' due
        # to 'plain' vs 'binary' pbms
        fuzzy_matches = ['pbm', 'bmp', 'cmuwm', 'epsi', 'eyuv', 'gem', 'gif', 'ilbm', 'pcx', 'png', 'ps', 'rast', 'rle', 'sgi', 'tga', 'tiff', 'winicon', 'xwd']
        conversions = {
                        '10x': 'data',
                        'ascii': 'ASCII text',
                        'atk': 'ASCII text',
                        #'bbnbg': 'empty',
                        'blu': 'Netpbm PGM "rawbits" image data',
                        'bmp': 'PC bitmap',
                        'cmuwm': 'CMU window manager raster image data',
                        'ddif': 'ddis/ddif',
                        'epsi': 'PostScript document text conforming',
                        'epson': 'data',
                        'eyuv': ('data' if self.lsb_release['Release'] >= 12.04 else 'DOS executable (device driver)'),
                        'fiasco': 'data',
                        'fits': 'FITS image data, 8-bit, character or unsigned binary integer',
                        'g3': 'data',
                        'gem': 'GEM Image data',
                        'gif': 'GIF image data, version',
                        'go': 'data',
                        'grn': 'Netpbm PGM "rawbits" image data',
                        'icon': ('ASCII text' if self.lsb_release['Release'] >= 12.04 else 'ASCII C program text'),
                        'icr': 'ASCII text, with very long lines, with no line terminators, with escape sequences',
                        'ilbm': 'IFF data, ILBM interleaved image',
                        'jpeg': 'JPEG image data, JFIF standard 1.01',
                        'jpg': 'JPEG image data, JFIF standard 1.01',
                        'leaf': 'data',
                        'lj': 'HP PCL printer data',
                        'macp': 'data',
                        'map': 'Netpbm PPM "rawbits" image data',
                        #'mda': 'empty',
                        'mgr': 'MGR bitmap, modern format, 8-bit aligned',
                        'mitsu': 'data',
                        #'mpeg': 'empty',
                        #'neo': 'empty',
                        'nokia': 'ASCII text, with no line terminators',
                        'palm': 'data',
                        'pbm': 'Netpbm PBM ',
                        #'pgm': 'empty',
                        'pcx': 'PCX ver. 3.0 image data',
                        'pgm': 'Netpbm PGM "rawbits" image data',
                        'pi1': 'data',
                        'pi3': 'data',
                        'pict': 'data',
                        'pj': 'HP PCL printer data',
                        'plot': 'data',
                        'png': 'PNG image',
                        'pnm': 'Netpbm PPM "rawbits" image data',
                        'ppa': 'data',
                        'ppm': 'Netpbm PPM "rawbits" image data',
                        'ps': 'PostScript document',
                        'psg3': 'PostScript document text conforming DSC level 3.0',
                        'ptx': 'data',
                        'puzz': 'data',
                        'rast': 'Sun raster image data',
                        'rle': 'RLE image data',
                        'red': 'Netpbm PGM "rawbits" image data',
                        #'rgb3': 'empty',
                        'sgi': 'SGI image data',
                        'sir': 'Solitaire Image Recorder format MGI Type 11',
                        'sixel': 'Non-ISO extended-ASCII text, with very long lines',
                        'tga': 'Targa image data',
                        'tiff': 'TIFF image data',
                        'uil': 'ASCII text',
                        'wbmp': 'data',
                        'winicon': 'MS Windows icon resource',
                        'x10bm': 'ASCII text',
                        'xbm': ('ASCII text' if self.lsb_release['Release'] >= 12.04 else 'ASCII C program text'),
                        'xpm': ('X pixmap image, ASCII text' if self.lsb_release['Release'] >= 12.04 else 'X pixmap image text'),
                        'xwd': 'XWD X Window Dump image data',
                        'ybm': 'data',
                        'yuv': '8086 relocatable (Microsoft)',
                        #'yuvsplit': 'empty',
                        'zinc': 'ASCII text',
                      }

        if self.lsb_release['Release'] == 8.04:
            conversions['yuv'] = '\\012- 8086 relocatable (Microsoft)'
            conversions['ybm'] = '\\012- Assembler source'
        if self.lsb_release['Release'] <= 8.04:
            conversions['winicon'] = 'MPEG sequence'
        if self.lsb_release['Release'] < 8.04:
            conversions['ddif'] = 'MPEG ADTS, layer I, v1, 224 kBits, 2x Monaural'
            conversions['eyuv'] = 'MPEG ADTS, layer I, v1, Monaural'
            conversions['ybm'] = 'Bennet Yee\'s "face" format'

        (rc, report) = testlib.cmd(["/usr/bin/file", "-b", os.path.join(self.tempdir, filename)])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        result = 'Mime type \'%s\' from file: %s, expected: %s\n' % (filetype, report, conversions[filetype])
        if filetype in fuzzy_matches:
            self.assertTrue(report.rstrip().startswith(conversions[filetype]), result + report)
        else:
            self.assertEquals(report.rstrip(), conversions[filetype], result + report)


    def test_conversions(self):
        '''Test conversion utilities'''
        #               ('type', 'command', 'outtype', 'reverse operation'),
        conversions = [ 
                        # pbmto...
                        ('pbm', 'pbmto10x', '10x', False),
                        ('pbm', 'pbmtoascii', 'ascii', False),
                        ('pbm', 'pbmtoatk', 'atk', True),
                        #('pbm', 'pbmtobbnbg', 'bbnbg', False), # empty
                        ('pbm', 'pbmtocmuwm', 'cmuwm', False), # error (reverse)
                        ('pbm', 'pbmtoepsi', 'epsi', False),
                        ('pbm', 'pbmtoepson', 'epson', False),
                        ('pbm', 'pbmtog3', 'g3', True),
                        ('pbm', 'pbmtogem', 'gem', True),
                        ('pbm', 'pbmtogo', 'go', False),
                        ('pbm', 'pbmtoicon', 'icon', True),
                        ('pbm', 'pbmtolj', 'lj', False),
                        ('pbm', 'pbmtomacp', 'macp', True),
                        #('pbm', 'pbmtomda', 'mda', True), # segfault
                        ('pbm', 'pbmtomgr', 'mgr', True),
                        ('pbm', 'pbmtonokia', 'nokia', False),
                        #('pbm', 'pbmtopgm', 'pgm', True), # empty, pbmtopgm w h <pbmfile>
                        ('pbm', 'pbmtopi3', 'pi3', True),
                        ('pbm', 'pbmtoplot', 'plot', False),
                        #('pbm', 'pbmtoppa', 'ppa', False), # error
                        ('pbm', 'pbmtoptx', 'ptx', False),
                        ('pbm', 'pbmtowbmp', 'wbmp', True),
                        ('pbm', 'pbmtox10bm', 'x10bm', False),
                        ('pbm', 'pbmtoxbm', 'xbm', True),
                        ('pbm', 'pbmtoybm', 'ybm', True),
                        ('pbm', 'pbmtozinc', 'zinc', False),

                        # ppmto...
                        ('ppm', 'ppmtobmp', 'bmp', True),
                        ('ppm', 'ppmtoeyuv', 'eyuv', False), # error (reverse)
                        ('ppm', 'ppmtogif', 'gif', False),
                        ('ppm', 'ppmtoicr', 'icr', False),
                        ('ppm', 'ppmtoilbm', 'ilbm', True),
                        ('ppm', 'ppmtojpeg', 'jpeg', False),
                        ('ppm', 'ppmtoleaf', 'leaf', False), # error (reverse)
                        ('ppm', 'ppmtolj', 'lj', False),
                        ('ppm', 'ppmtomap', 'map', False),
                        ('ppm', 'ppmtomitsu', 'mitsu', False),
                        #('ppm', 'ppmtompeg', 'mpeg', False), # error
                        #('ppm', 'ppmtoneo', 'neo', True), # error
                        ('ppm', 'ppmtopcx', 'pcx', True),
                        ('ppm', 'ppmtopgm', 'pgm', False), # hangs (reverse)
                        ('ppm', 'ppmtopi1', 'pi1', True),
                        ('ppm', 'ppmtopict', 'pict', False),
                        ('ppm', 'ppmtopj', 'pj', True),
                        ('ppm', 'ppmtopuzz', 'puzz', False),
                        #('ppm', 'ppmtorgb3', 'rgb3', True), # empty
                        ('ppm', 'ppmtosixel', 'sixel', False),
                        ('ppm', 'ppmtotga', 'tga', True),
                        ('ppm', 'ppmtouil', 'uil', False),
                        ('ppm', 'ppmtowinicon', 'winicon', True),
                        ('ppm', 'ppmtoxpm', 'xpm', True),
                        ('ppm', 'ppmtoyuv', 'yuv', False), # yuvtoppm <width> <height> [yuvfile]
                        #('ppm', 'ppmtoyuvsplit', 'yuvsplit', True), # hangs

                        ('pnm', 'pnmtoddif', 'ddif', False),
                        #('pnm', 'pnmtofits', 'fits', True), # segfault
                        ('pnm', 'pnmtojpeg', 'jpeg', True),
                        #('pnm', 'pnmtopalm', 'palm', True), # error
                        ('pnm', 'pnmtopng', 'png', True),
                        ('pnm', 'pnmtops', 'ps', False), # reverse is empty
                        ('pnm', 'pnmtorast', 'rast', True),
                        ('pnm', 'pnmtorle', 'rle', True),
                        ('pnm', 'pnmtosgi', 'sgi', True),
                        ('pnm', 'pnmtosir', 'sir', True),
                        ('pnm', 'pnmtotiff', 'tiff', False), # reverse fails
                        ('pnm', 'pnmtotiffcmyk', 'tiff', False),
                        ('pnm', 'pnmtoxwd', 'xwd', True),

                        # ...topnm
                        ('gif', 'giftopnm', 'pnm', False),
                        #('bmp', 'bmptopnm', 'pnm', False),
                      ]

        if self.lsb_release['Release'] >= 12.04:
            conversions.append(('pbm', 'pbmtopsg3', 'psg3', False))
        else:
            conversions.append(('pnm', 'pnmtofiasco', 'fiasco', False)) # bug 914191

        ppmq256 = ['gif', 'icr', 'pcx', 'pict', 'puzz', 'sixel', 'uil', 'winicon']
        ppmq16 = ['neo', 'pi1']
        print ""
        for infiletype, command, outfiletype, do_reverse in conversions:
            if self.lsb_release['Release'] > 8.04 and self.lsb_release['Release'] <= 9.04:
                if outfiletype == 'uil':
                    print "  uil: skipped (can't find rgb.txt on system)"
                    continue
            for direction in ['', "reverse"]:
                cmd = command
                origpath = "./data/well-formed." + infiletype
                infilename = os.path.join(self.tempdir, cmd + "." + infiletype)
                outfilename = cmd + "." + outfiletype

                if direction == '':
                    shutil.copy(origpath, infilename)

                if direction == "reverse":
                    if do_reverse:
                        cmd = re.sub(r'%sto' % infiletype, '', command)
                        cmd += 'to'
                        cmd += re.sub(r'to%s' % outfiletype, '', command)

                        tmp = infiletype
                        infiletype = outfiletype
                        outfiletype = tmp
                        infilename = os.path.join(self.tempdir, outfilename)
                        outfilename = cmd + "." + outfiletype
                    else:
                        continue

                print "  %s" % (cmd)
                #print "    infilename: " + infilename
                #print "    outfilename: " + outfilename
                #print "    infiletype: " + infiletype
                #print "    outfiletype: " + outfiletype

                # some file need to be adjusted a tad
                if infiletype == "ppm":
                    tmpinfile = os.path.join(self.tempdir, os.path.basename(infilename) + ".tmp")
                    if outfiletype in ppmq256:
                        self._ppmquant_file(infilename, tmpinfile, "256")
                        infilename = tmpinfile
                    elif outfiletype in ppmq16:
                        self._ppmquant_file(infilename, tmpinfile, "16")
                        infilename = tmpinfile
                elif infiletype == "pnm":
                    tmpinfile = os.path.join(self.tempdir, os.path.basename(infilename) + ".tmp")
                    if outfiletype in ['rast', 'tiff', 'xwd', 'palm']:
                        self._ppmquant_file(infilename, tmpinfile, "256")
                        infilename = tmpinfile

                (rc, report) = testlib.cmd(["/usr/bin/" + cmd, "-quiet", infilename])
                expected = 0
                result = 'Got exit code %d, expected %d for \'%s\'\n' % (rc, expected, cmd)
                self.assertEquals(expected, rc, result + report)

                # write out the converted image file
                self._write_file(outfilename, report)

                # Let's check the mime-type to make sure it generated a valid image
                self._check_mime_type(outfilename, outfiletype)


    def test_cve_2008_0554(self):
        '''Test for CVE-2008-0554 segfault'''

        (rc, report) = testlib.cmd(["/usr/bin/giftopnm", "-quiet", "netpbm-free/CVE-2008-0554.gif"])
        expected = 1
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)


if __name__ == '__main__':
    unittest.main()

