#!/usr/bin/python
#
#    testlib_multimedia.py quality assurance test script
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
#    along with this program.  If not, see <httpd://www.gnu.org/licenses/>.
#

# QRT-Depends: testlib_multimedia

import subprocess
import os
import sys
import tempfile
import testlib
import time
import urllib2
import urllib

topurl = "http://samples.mplayerhq.hu/"
#topurl = "http://ftp.icm.edu.pl/packages/mplayer/samples/" # seems to be a mirror
topdir = os.path.join(os.getcwd(), "testlib_multimedia")
files = [ 'asf-wmv/welcome3.wmv',
          'asf-wmv/Alice Deejay - Back In My Life.asf',
          'FLV/zelda.flv',
          'flac/dilvie_-_the_dragonfly.flac',
          'game-formats/film-cpk/intro.film',
          'game-formats/film-cpk/R01.CAK',
          'game-formats/film-cpk/corelogo-stereo.cpk',
          'Matroska/vorbis-audio-switch.mkv',
          'Matroska/subtitles/test_01.mkv',
          'mov/NNM3022_LiquidArmor_ISDN.mov',
          'MPEG-4/test_qcif_200_aac_64.mp4',
          'game-formats/wc3-mve/wc3-arrest.mve',                # crasher
          'A-codecs/speex/talk109-q5.spx',                      # very quiet
          'A-codecs/AAC/ct_faac-adts.aac',
          'A-codecs/AC3/Broadway-5.1-48khz-448kbit.ac3',
          'A-codecs/musepack/01 - Right Here, Right Now.mpc',
          'A-codecs/vorbis/floor_type_0/01_Duran_Duran_Planet_Earth.ogg',
          'A-codecs/lossless/luckynight.shn',
          'A-codecs/MP3/Ed_Rush_-_Sabotage.mp3',
          'tta/sf_44khz_stereo_16bit.tta',
#          'Matroska/realaudio/nosound.mkv',
#          'Matroska/Mushishi24-head.mkv',
#          'Matroska/theora.mkv',
#          'asf-wmv/Saolin.audio_0x75-VoxwareMetaSound.V4CC_MP42.asf',
#          'A-codecs/WMA/wnrn.asx',
#          'asf-wmv/The_Matrix_2.asf',
#          'asf-wmv/elephant.asf',
#          'asf-wmv/vegitavscell2.asf',
#          'MPEG-4/encoded.m4v',
#          'MPEG-4/mp3-in-mp4/[A-Destiny]_Konjiki_no_Gash_Bell_-_65_[71EE362C].mp4',
#          'mov/yuv2.mov',
#          'real/rockfall.rm',
#          'real/spear.rm',
#          'real/mp3_in_rm/iwantcandy.mp3.rm',
#          'FLV/asian-commercials-are-weird.flv',
#          'FLV/flash8/tacoma.flv',
#          'flac/24-bit_96kHz_RICE2_pop.flac',
          'A-codecs/ATRAC3/mc_sich_at3_066.wav']

class MultimediaCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self):
        '''Setup'''
        self.release = testlib.ubuntu_release()
        self.assertFalse(os.getuid() == 0, "ERROR: must not be root")

    def _cmd(self, command, files, extension, topdir=topdir, expected=0, add_file_url=True, search=""):
        '''Execute command on files with the specified extension'''
        count = 0
        num = len(files)
        for f in files:
            count += 1
            dir = os.path.dirname(f)
            name = os.path.basename(f)
            path = os.path.join(topdir, dir, name)
            if not os.path.exists(path):
                self._skipped("Couldn't find %s" % (path))
                continue

            if name.endswith('.' + extension):
                print >>sys.stdout, "(%d of %d: Trying %s with %s) " % (count, num, name, command[0])
                sys.stdout.flush()
                file_url = "file:///" + path
                if not add_file_url:
                    file_url = path
                rc, report = testlib.cmd(command + [file_url])
                if expected != None:
                    result = 'Got exit code %d, expected %d\n' % (rc, expected)
                    self.assertEquals(expected, rc, result + report)
                if search != "":
                    self.assertTrue(search in report, "Could not find '%s' in report:\n%s" % (search, report))

    def _player_cmd(self, command, filename, seconds=5):
        '''Play a file for certain number of seconds with command'''
        self.assertTrue(os.path.exists(filename), "Couldn't find %s" % (filename))

        # Chromium prompts for a search engine on first launch, short circuit
        # that.
        created_first_run = False
        first_run = ""
        if command == "chromium-browser":
            first_run = os.path.join(os.path.expanduser('~'), '.config/chromium', 'First Run')
            if not os.path.exists(first_run):
                if not os.path.exists(os.path.dirname(first_run)):
                    os.mkdir(os.path.dirname(first_run))
                    # Only set this here so our cleanup won't remove user
                    # configuration
                    created_first_run = True
                testlib.cmd(['touch', first_run])

        self.listener = os.fork()
        if self.listener == 0:
            args = ['/bin/sh', '-c', 'exec %s %s >/dev/null 2>&1' % (command, filename)]
            os.execv(args[0], args)
            sys.exit(0)
        time.sleep(seconds)
        pid, status = os.waitpid(self.listener, os.WNOHANG)
        rc = status >> 8            # return code is upper byte
        status = status & 0x7f      # status is lower 7 bits
        try:
            os.kill(self.listener, 15)
        except:
            pass

        # Cleanup any first run files before asserting things
        if created_first_run and first_run != "" and os.path.exists(first_run):
            if command == "chromium-browser":
                time.sleep(3) # wait for chromium to shut down
            testlib.recursive_rm(os.path.dirname(first_run))

        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result)

def download(files, topurl=topurl, topdir=topdir):
    '''Download files based on hierarchy in
       http://samples.mplayerhq.hu/allsamples.txt'''

    if os.getuid() == 0:
        print >> sys.stderr, "ERROR: must not be root to download"
        sys.exit(1)

    if not os.path.exists(topdir):
        os.mkdir(topdir)

    print "Downloading files from %s\n" % (topurl)

    for f in files:
        os.chdir(topdir)
        dir = os.path.join(topdir, os.path.dirname(f))
        name = os.path.basename(f)

        if not os.path.exists(dir):
            subprocess.call(['/bin/mkdir', '-p', dir])
        os.chdir(dir)

        url = topurl + urllib.quote(f.lstrip('./'))
        sys.stdout.write("%s:\n" % (name))

        if os.path.exists(name):
            print "  skipping (already exists)"
            continue

        opener = urllib2.build_opener()
        try:
            page = opener.open(url)
        except urllib2.HTTPError, e:
            sys.stdout.write(str(e) + "\n")
            continue

        try:
            tmp, tmpname = tempfile.mkstemp()
        except Exception:
            raise
        os.write(tmp, page.read())
        os.close(tmp)
        subprocess.call(['mv', '-f', tmpname, name])

        sys.stdout.write("  done\n")

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == "download":
        download(files)
