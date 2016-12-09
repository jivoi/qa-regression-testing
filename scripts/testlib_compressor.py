#!/usr/bin/python
#
#    testlib_compressor.py quality assurance library
#    Copyright (C) 2010 Canonical Ltd.
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
Classes to help with testing file compressors. Example usage:

#!/usr/bin/python

# QRT-Packages: file

import unittest, subprocess, sys
import testlib
import testlib_compressor

class TestFoo(testlib_compressor.CompressorCommon):
    def setUp(self):
        \'''Set up prior to each test_* function\'''
        testlib_compressor.CompressorCommon._setUp(self)
        self.extension = ".fooz"

    def tearDown(self):
        \'''Clean up after each test_* function\'''
        testlib_compressor.CompressorCommon._tearDown(self)

    def test_foo(self):
        \'''Test foo\'''
        # see testlib_compressor._compress() for details
        self._compress(["/bin/fzip", "-c"], ["/bin/funzip", "-c"], ["/bin/fzip", "-t"], self.extension, r"fzip compressed data.*", "./data/foo")

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestFoo))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
'''

import testlib
import os
from stat import ST_SIZE
import sys
import tempfile

class CompressorCommon(testlib.TestlibCase):
    '''Common functions'''
    def _setUp(self):
        '''Set up prior to each test_* function'''
        runshm = "/run/shm"
        devshm = "/dev/shm"

        base_tmp = "/tmp"
        if os.path.isdir(runshm) and not os.path.islink(runshm):
            base_tmp = runshm
        elif os.path.isdir(devshm):
            base_tmp = devshm

        self.debug = False
        if self.debug:
            print "  debug: base_tmp is %s" % (base_tmp)

        self.tempdir = tempfile.mkdtemp(dir=base_tmp)

        self.maxsize = 0
        if base_tmp.endswith("shm"):
            args = ['df', '-P', '-B', '1']
            if self.lsb_release['Release'] >= 11.10:
                args.append('-x')
                args.append('fuse.gvfs-fuse-daemon')
            rc, report = rc, report = testlib.cmd(args)
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            result = "Couldn't find '%s' in report" % base_tmp
            self.assertTrue(base_tmp in report, result + report)

            for line in report.splitlines():
                if base_tmp in line:
                    self.maxsize = int(line.split()[1]) / 2
                    break
            if self.maxsize == 0:
                print "WARNING: could not determine size of '%s'" % (base_tmp)
            elif self.debug:
                print "  debug: maxsize is %d" % (self.maxsize)

    def _tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def _compress(self, compress_args, uncompress_args, test_args, extension, mime, fn):
        '''Test compress, decompress, mimetype and checksum on file.

           compress_args: binary and any options to compress to stdout
           uncompress_args: binary and any options to uncompress to stdout
           extension: extension for files compressed with this binary
           mime: mime type string to match for files compressed with this binary
           fn: file to check

           Eg:
           testlib_compressor._compress(["/bin/gzip", "-c"], ["/bin/gunzip", "-c"], ["/bin/gzip", "-t"], "gz", "gzip compressed data", /tmp/foo)
        '''

        # All of this is an attempt to be clever and compress/uncompress
        # normally, but uncompress/compress if the extension matches the
        # extension of the filename given.
        exe_args1 = compress_args
        exe_args2 = uncompress_args
        fn = fn
        out_file1 = os.path.join(self.tempdir, os.path.basename(fn)) + extension
        out_file2 = os.path.join(self.tempdir, os.path.basename(fn))
        compressed_file = out_file1
        (root, ext) = os.path.splitext(fn)
        if extension == ext:
            exe_args1 = uncompress_args
            exe_args2 = compress_args
            out_file1 = os.path.join(self.tempdir, os.path.basename(root))
            out_file2 = os.path.join(self.tempdir, os.path.basename(fn))
            compressed_file = out_file2

            # Integrety check the original file
            if self.debug:
                print "  debug: %s" % (" ".join(test_args + [fn]))
            (rc, report) = testlib.cmd(test_args + [fn])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

        # first pass
        if self.debug:
            print "  debug: %s > %s" % (" ".join(exe_args1 + [fn]), out_file1)
        (rc, report) = testlib.cmd(exe_args1 + [fn], stdout=file(out_file1, 'w'))
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # second pass
        if self.debug:
            print "  debug: %s > %s" % (" ".join(exe_args2 + [out_file1]), out_file2)
        (rc, report) = testlib.cmd(exe_args2 + [out_file1], stdout=file(out_file2, 'w'))
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Check the file-type to make sure it generated a compressed file
        if self.debug:
            print "  debug: check file type of '%s'" % compressed_file
        self.assertFileType(compressed_file, mime)

        # Integrity check the compressed file
        if self.debug:
            print "  debug: %s" % (" ".join(test_args + [compressed_file]))
        (rc, report) = testlib.cmd(test_args + [compressed_file])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # Get md5sums for original and uncompressed files. Only check
        # compress/uncompress since uncompress/compress could have used a
        # non-default compression level.
        if extension != ext:
            if self.debug:
                print "  debug: compare checksum of '%s' with '%s'" % (out_file2, fn)
            orig_md5 = testlib.get_md5(fn)
            uncomp_md5 = testlib.get_md5(out_file2)
            result = "md5sum %s doesn't match original: %s\n" % (uncomp_md5, orig_md5)
            self.assertEquals(orig_md5, uncomp_md5, result)
        elif self.debug:
            print "  debug: skipping checksum (may have non-default compression level)"

        os.unlink(out_file1)
        os.unlink(out_file2)

    def _rcompress(self, compress_args, uncompress_args, test_args, extension, mime, dirPath):
        names = os.listdir(dirPath)
        num = 0
        for name in names:
            path = os.path.join(dirPath, name)
            if not os.access(path, os.R_OK):
                print "  skipping %s (permission denied)" % (path)
                continue
            elif os.path.islink(path):
                # silently skip symlinks
                continue
            elif os.path.isfile(path):
                if self.maxsize > 0 and os.stat(path)[ST_SIZE]/1024 > self.maxsize:
                    print "  skipping %s (too big for %s)" % (path, self.tempdir)
                    continue
                print "  %s ..." % (path),
                if self.debug:
                    print ""
                sys.stdout.flush()
                self._compress(compress_args, uncompress_args, test_args, extension, mime, path)
                num += 1
                print "ok"
            elif os.path.isdir(path):
                if path == self.tempdir:
                    print "  skipping %s (don't scan self.tempdir)" % (path)
                    continue
                num += self._rcompress(compress_args, uncompress_args, test_args, extension, mime, path)
            else:
                print "  skipping %s (not a directory or regular file)" % (path)

        return num
