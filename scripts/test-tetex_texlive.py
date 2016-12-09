#!/usr/bin/python
#
#    test-tetex_texlive.py quality assurance test script
#    Copyright (C) 2008,2010 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#    Author: Marc Deslauriers <marc.deslauriers@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
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
# QRT-Packages: texlive-base-bin texlive-extra-utils texlive-latex-base texlive-latex-recommended
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: private/qrt/texlive.py


'''
  How to run:

    Hardy and later (texlive):
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install ghostscript texlive-base-bin texlive-extra-utils texlive-latex-base texlive-latex-recommended lsb-release && ./test-tetex_texlive.py -v'

    Dapper (tetex):
    $ sudo apt-get install tetex-bin tetex-extra (tetex)
    $ ./test-tetex_texlive.py -v'

'''

import unittest, subprocess, os, tempfile
import testlib
import sys

try:
    from private.qrt.texlive import PrivateTexliveTest
except ImportError:
    class PrivateTexliveTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class TexliveTest(testlib.TestlibCase, PrivateTexliveTest):
    '''Test tetex/texlive functionality'''

    def setUp(self):
        '''setUp'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="texlive-")

    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_dviljk(self):
        '''Test dviljk utilities'''

        self.tex = os.path.join(self.tempdir, "foo.tex")
        self.eps = os.path.join(self.tempdir, "foo.eps")
        output_file = os.path.join(self.tempdir, 'foo.lj')

        sample = '''\documentclass[12pt]{article}
\usepackage{epsfig}
\\begin{document}

  This is a very simple file, though it does include some mathematical 
  symbols, $\\beta, x$ and $y$,  and some equations,  
 \\begin{equation} 
 \\frac{1}{2} + \\frac{1}{5} =  \\frac{7}{10}. 
  \end{equation} 

 The equations are automatically numbered:
\\begin{equation} 
 1 + 1 = 2 \Rightarrow E = m c^2.  
\end{equation}  

  \LaTeX\ can handle complicated mathematical expressions. 
 \\begin{equation} 
 \int_0^\infty \cos (k t) e^{-s t} d t = \\frac{s}{s^2 + k^2}
 \end{equation} 
 if $s > 0$. 
 \\begin{equation}
 e^z = \sum_{n=0}^\infty \\frac{ z^n}{n!} . 
 \end{equation} 

 Leave a blank line in your file when you want a new paragraph. 
      \LaTeX\ will automatically 
 arrange your text
              into tidy lines of 
 even length, even 
 if the 
 original text in the .tex file is a mess. 

\\begin{figure}[htbp]
\centering
\epsfig{file=''' + self.eps + ''', width=\\textwidth}
\caption{ Caption text. }
\label{fig:example}
\end{figure}


\end{document}
'''

        eps = '''%!PS-Adobe-3.0 EPSF-3.0
%%Creator: GIMP PostScript file plugin V 1.17 by Peter Kirchgessner
%%Title: test.eps
%%CreationDate: Wed Dec  5 15:56:20 2007
%%DocumentData: Clean7Bit
%%LanguageLevel: 2
%%Pages: 1
%%BoundingBox: 14 14 17 17
%%EndComments
%%BeginProlog
% Use own dictionary to avoid conflicts
10 dict begin
%%EndProlog
%%Page: 1 1
% Translate for offset
14.173228346456694 14.173228346456694 translate
% Translate to begin of first scanline
0 2.3999999999999999 translate
2.3999999999999999 -2.3999999999999999 scale
% Image geometry
10 10 8
% Transformation matrix
[ 10 0 0 10 0 0 ]
% Strings to hold RGB-samples per scanline
/rstr 10 string def
/gstr 10 string def
/bstr 10 string def
{currentfile /ASCII85Decode filter /RunLengthDecode filter rstr readstring pop}
{currentfile /ASCII85Decode filter /RunLengthDecode filter gstr readstring pop}
{currentfile /ASCII85Decode filter /RunLengthDecode filter bstr readstring pop}
true 3
%%BeginData:          221 ASCII Bytes
colorimage
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
p\o[~>
pAf^~>
pAf^~>
%%EndData
showpage
%%Trailer
end
%%EOF
'''

        try:
            fh = open(self.tex, 'w')
            fh.write(sample)
            fh.close()
            fh = open(self.eps, 'w')
            fh.write(eps)
            fh.close()
        except:
            raise

        self.assertTrue(subprocess.call(['latex', '-output-directory=' + self.tempdir, self.tex], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0)

        for exe in ['dvilj', 'dvilj4', 'dvilj4l', 'dvilj2p']:
            self.assertTrue(subprocess.call([exe, '-s2', '-e' + output_file, os.path.join(self.tempdir, 'foo.dvi')], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0)
            os.unlink(output_file)


    def test_CVE_2007_5935(self):
        '''CVE_2007_5935'''

        output_file = os.path.join(self.tempdir, 'file.ps')

        bad = '''\documentclass{article}

\usepackage[hypertex]{hyperref}

\\begin{document}

\href{/XXXX/XXXXXXX/XXX/XXXXX/XXXXXXXXXXXXXXX/XXXXXXX/XXXXXXXXXXXXXXXXX/XXXXXXXXXX XXXXXXXXXXXXXXXXXXX/XXXXXXXXXX XXXXX XXXXXXXXXXXXX - XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}{solot}

\end{document}
'''

        self.tex = os.path.join(self.tempdir, "foo.tex")
        try:
            fh = open(self.tex, 'w')
            fh.write(bad)
            fh.close()
        except:
            raise

        self.assertTrue(subprocess.call(['latex', '-output-directory=' + self.tempdir, self.tex], stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0)

        current_dir = os.getcwd()
        os.chdir(self.tempdir)

        return_code = subprocess.call(['dvips', '-o', output_file, '-z', os.path.join(self.tempdir, 'foo.dvi')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        os.chdir(current_dir)
        self.assertTrue(return_code == 0)
        

if __name__ == '__main__':
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TexliveTest))
    rc = unittest.TextTestRunner(verbosity=2).run(suite)
    if not rc.wasSuccessful():
        sys.exit(1)
