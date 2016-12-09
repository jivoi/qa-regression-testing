#!/usr/bin/python
#
#    test-qt4-x11.py quality assurance test script for qt4-x11
#    Copyright (C) 2009-2013 Canonical Ltd.
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
# packages required for test to run:
# QRT-Packages: build-essential g++ libqt4-dev
# files and directories required for the test to run:
# QRT-Depends: qt4-x11 ssl data

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -- sh -c 'apt-get -y install PKG  && ./test-qt4-x11.py -v'
'''

import unittest, subprocess
import os
import shutil
import testlib
import tempfile

class QT4Test(testlib.TestlibCase):
    '''Test qt4-x11'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tmpdir = ""
        self.current_dir = os.getcwd()

    def tearDown(self):
        '''Clean up after each test_* function'''
        os.chdir(self.current_dir)
        if os.path.exists(self.tmpdir):
            testlib.recursive_rm(self.tmpdir)

    def test_CVE_2009_2700(self):
        '''Test CVE-2009-2700'''
        #subprocess.call(['bash'])
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "CVE-2009-2700.c")
        binary = os.path.join(self.tmpdir, "CVE-2009-2700")
        shutil.copy('./qt4-x11/CVE-2009-2700.c', source)

        pkg_config = testlib.get_pkgconfig_flags(['QtNetwork', 'QtTest'])
        rc, report = testlib.cmd(['g++', source, '-o', binary] + pkg_config)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_CVE_2013_4549(self):
        '''Test CVE-2013-4549'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "CVE-2013-4549.c")
        binary = os.path.join(self.tmpdir, "CVE-2013-4549")
        shutil.copy('./qt4-x11/CVE-2013-4549/CVE-2013-4549.c', source)
        shutil.copy('./qt4-x11/CVE-2013-4549/1-levels-nested-dtd.xml', self.tmpdir)
        shutil.copy('./qt4-x11/CVE-2013-4549/2-levels-nested-dtd.xml', self.tmpdir)
        shutil.copy('./qt4-x11/CVE-2013-4549/internal-entity-polynomial-attribute.xml', self.tmpdir)

        pkg_config = testlib.get_pkgconfig_flags(['QtXml'])
        rc, report = testlib.cmd(['g++', source, '-o', binary] + pkg_config)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        os.chdir(self.tmpdir)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def _load_tiff(self, fn):
        '''Load tiff file'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "loader.c")
        binary = os.path.join(self.tmpdir, "loader")
        tiff = os.path.join(self.tmpdir, os.path.basename(fn))
        shutil.copy(fn, tiff)

        contents = '''
#include <QtCore/QCoreApplication>
#include <QtGui/QImage>

int main(int argc, char *argv[])
{ QImage img("%s"); }
''' % (tiff)
        testlib.config_replace(source, contents)

        pkg_config = testlib.get_pkgconfig_flags(['QtGui'])
        rc, report = testlib.cmd(['g++', source, '-o', binary] + pkg_config)
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        rc, report = testlib.cmd([binary])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_tiff(self):
        '''Test tiff loading'''
        print ""
        for i in ['./data/well-formed.tif', './data/well-formed.tiff', './data/well-formed-gray.tiff', './data/well-formed-gray16.tiff']:
            print "  %s" % i
            self._load_tiff(i)

    def test_CVE_2011_3194(self):
        '''Test CVE-2011-3194'''
        print ""
        for i in ['./qt4-x11/CVE-2011-3194/blocks-hp-mask.tif', './qt4-x11/CVE-2011-3194/blocks-hp-mask.tif', './qt4-x11/CVE-2011-3194/qtbug-19878.tiff']:
            print "  %s" % i
            self._load_tiff(i)

    def test_font(self):
        '''Test font loading'''
        self.tmpdir = tempfile.mkdtemp(prefix='testlib', dir='/tmp')
        source = os.path.join(self.tmpdir, "loader.c")
        binary = os.path.join(self.tmpdir, "loader")
        pkg_config = testlib.get_pkgconfig_flags(['QtGui'])
        os.environ['DISPLAY'] = ":0.0"

        # First, get all the fonts
        rc, report = testlib.cmd(['fc-list'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        fonts = []
        for line in report.splitlines():
            font = line.split(':')[0].split(',')[0]
            if not font in fonts:
                fonts.append(font)
        fonts.sort()

        print ""
        for f in fonts:
            print "  %s" % f
            contents = '''
#include <QtGui/QApplication>
#include <QtGui/QTextEdit>
int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QTextEdit text;
    text.document()->setDefaultFont(QFont("%s", 25));
    text.document()->setPlainText(QString::fromUtf8("%s: a\u0323\u0303"));
    text.show ();
    //return app.exec(); // this opens the gui, but not really needed for this
}
''' % (f, f)

            testlib.config_replace(source, contents)

            rc, report = testlib.cmd(['g++', source, '-o', binary] + pkg_config)
            expected = 0
            result = 'Got exit code %d, expected %d\nSource:\n%s\n\n' % (rc, expected, contents)
            self.assertEquals(expected, rc, result + report)

            rc, report = testlib.cmd([binary])
            expected = 0
            result = 'Got exit code %d, expected %d\n' % (rc, expected)
            self.assertEquals(expected, rc, result + report)

            os.unlink(source)
            os.unlink(binary)


if __name__ == '__main__':
    # simple
    unittest.main()
