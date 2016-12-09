#!/usr/bin/python
#
#    test-bogofilter.py quality assurance test script for bogofilter
#    Copyright (C) 2010-2012 Canonical Ltd.
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
# QRT-Packages: bogofilter
# packages where more than one package can satisfy a runtime requirement:
# QRT-Alternates: 
# files and directories required for the test to run:
# QRT-Depends: bogofilter
# privilege required for the test to run (remove line if running as user is okay):
# QRT-Privilege: root

'''
    How to run against a clean schroot named 'hardy':
        schroot -c hardy -u root -- sh -c 'apt-get -y install lsb-release bogofilter && ./test-bogofilter.py -v'
'''


import unittest, subprocess, sys, os, tempfile
import testlib

try:
    from private.qrt.bogofilter import PrivateBogofilterTest
except ImportError:
    class PrivateBogofilterTest(object):
        '''Empty class'''
    print >>sys.stdout, "Skipping private tests"

class BogofilterTest(testlib.TestlibCase, PrivateBogofilterTest):
    '''Test bogofilter.'''

    def setUp(self):
        '''Set up prior to each test_* function'''
        self.tempdir = tempfile.mkdtemp(dir='/tmp',prefix="bogofilter-")

        rc, report = testlib.cmd(['tar', '-C', self.tempdir, '-zxv', '-f', './bogofilter/part1.tar.gz'])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        # learn spam
        self.assertEquals(subprocess.call(['bash', '-c', 'cat %s/part1/spm* | /usr/bin/bogofilter -s -d %s' % (self.tempdir,self.tempdir)]),0,"Learning spam")

        # learn ham
        self.assertEquals(subprocess.call(['bash', '-c', 'cat %s/part1/[35]* | /usr/bin/bogofilter -n -d %s' % (self.tempdir,self.tempdir)]),0,"Learning ham")


    def tearDown(self):
        '''Clean up after each test_* function'''
        if os.path.exists(self.tempdir):
            testlib.recursive_rm(self.tempdir)

    def test_known_spam(self):
        '''Test Known Spam'''

        script = os.path.join(self.tempdir, "known_spam.mbox")
        contents = '''From evilspammer@example.com Wed Aug 25 08:37:58 2010
Received: from mitnick ([100.100.100.1]) by gulp.example.org
 (Sun Java(tm) System Messaging Server 6.3-8.01 (built Dec 16 2008; 32bit))
 with ESMTP id <0L7P00I5MKES8610@gulp.example.org> for
 ubuntuuser@example.org; Wed, 25 Aug 2010 08:37:58 -0400 (EDT)
Date: Wed, 25 Aug 2010 06:37:48 -0700
From: Ron Polepeil <evilspammer@example.com>
Subject: This is spam
In-reply-to: <050a01cb422e$12dc46e5$b488e29e@435wdih>
X-Sender: <evilspammer@>
To: ubuntuuser@example.org
Reply-to: Ron Polepeil <evilspammer@example.com>
Message-id: <2.2.32.201007251337480052bd7b@example.org>
MIME-version: 1.0
Content-Transfer-Encoding: 7bit
Content-Type: text/plain; charset="us-ascii"; Format="flowed"

economical hunting vacation of your life people sellin
g you their product imagine selling a product fo
r only 57 million email addresses for only $ 99 the gold marketing setup
virtually everything bill selected amount to your account plus the
following shipping costs not interested in sexually explicit material
free loan evaluation value of your home our founding fathers
your package includes unlimited free phone consultations people are making
that kind of money right now by doing the same thing selected amount to
your account plus the following shipping costs interested in hypnosis
quitting smoking amazingly low rates complete guide to lowering your
mortgage investment of several thousand dollars you may fax your order
targeted lists of email addresses print advertising
'''
        testlib.create_fill(script, contents, mode=0755)

        # Bogofilter should think this is spam
        rc, report = testlib.cmd(['bogofilter', '-vv', '-d', self.tempdir, '-B', script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected = "X-Bogosity: Spam"
        result = "Couldn't find %s in %s!!!\n" % (expected, report)
        self.assertTrue(expected in report, result)

    def test_learning(self):
        '''Test Learning Spam'''

        script = os.path.join(self.tempdir, "learning_spam.mbox")
        contents = '''From evilspammer@example.com Wed Aug 25 08:37:58 2010
Received: from mitnick ([100.100.100.1]) by gulp.example.org
 (Sun Java(tm) System Messaging Server 6.3-8.01 (built Dec 16 2008; 32bit))
 with ESMTP id <0L7P00I5MKES8610@gulp.example.org> for
 ubuntuuser@example.org; Wed, 25 Aug 2010 08:37:58 -0400 (EDT)
Date: Wed, 25 Aug 2010 06:37:48 -0700
From: Ron Polepeil <evilspammer@example.com>
Subject: Viagra100mg $1.87, Cialis20mg $2.97 + Lowest Price and Best
 Quality Guaranteeed. skj0
In-reply-to: <050a01cb422e$12dc46e5$b488e29e@435wdih>
X-Sender: <evilspammer@>
To: ubuntuuser@example.org
Reply-to: Ron Polepeil <evilspammer@example.com>
Message-id: <2.2.32.201007251337480052bd7b@example.org>
MIME-version: 1.0
Content-Transfer-Encoding: 7bit
Content-Type: text/plain; charset="us-ascii"; Format="flowed"

Wow! Viagra is pretty cool! You should purchase Viagra _today_!!!

Anyway, like I was sayin', Viagra is the fruit of medications. You can
barbecue it, boil it, broil it, bake it, saute it. Dey's uh, Viagra-kabobs,
Viagra creole, Viagra gumbo. Pan fried, deep fried, stir-fried. There's
pineapple Viagra, lemon Viagra, coconut Viagra, pepper Viagra, Viagra soup,
Viagra stew, Viagra salad, Viagra and potatoes, Viagra burger, Viagra
sandwich. That- that's about it.

Ubuntu users get 10.04% off their first purchase!

Why settle for Canadian Meds, when you can get 100% generic Viagra!

We could also call this Cialis, but why bother?

For a limited-time only: free high-school diploma with every purchase of
Viagra!

Your life will look better with a jackpot in your pocket!

There's nothing that quite says "I love you" than renewing your wedding
vows with a purchase of generic 100% counterfeit spam pills that kind of
look like Viagra.

Our pills are now lactose-free! We've replaced the lactose dilutant with
melamine, for allergy-free lovin'!

Keep falling out of bed? Take some Viagra and stop rolling in your sleep.

This is to fool your spam filter: V i4g r4 c1 4 l1s <- we're clever!

This is also to fool your spam filter: Ask him to send you the total of
$1,200,000.00 in a certified bank cheque which I kept for your
compensation. In the moment, I'm very busy here because of the investment
projects which the new partner and I are having at hand, finally remember
to send your current information to him as below.
'''
        testlib.create_fill(script, contents, mode=0755)

        # Bogofilter should be unsure
        rc, report = testlib.cmd(['bogofilter', '-vv', '-d', self.tempdir, '-B', script])
        expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected = "X-Bogosity: Unsure"
        result = "Couldn't find %s in %s!!!\n" % (expected, report)
        self.assertTrue(expected in report, result)

        # Now, learn it
        self.assertEquals(subprocess.call(['bash', '-c', 'cat %s | /usr/bin/bogofilter -s -d %s' % (script,self.tempdir)]),0,"Learning spam")

        # Try again, it should now be spam
        rc, report = testlib.cmd(['bogofilter', '-vv', '-d', self.tempdir, '-B', script])
        expected = 0
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

        expected = "X-Bogosity: Spam"
        result = "Couldn't find %s in %s!!!\n" % (expected, report)
        self.assertTrue(expected in report, result)

    def test_cve_2010_2494(self):
        '''Test CVE-2010-2494'''

        script = os.path.join(self.tempdir, "cve_2010_2494.mbox")
        contents = '''Content-Type: multipart/mixed;boundary="----bound"

------bound
Content-Transfer-Encoding: base64


=C7ET=DDNERSAVA=DE=20
------bound
Content-Type: text/plain; charset="iso-8859-9"
'''
        testlib.create_fill(script, contents, mode=0755)

        rc, report = testlib.cmd(['bogofilter', '-vv', '-d', self.tempdir, '-B', script])
        expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

    def test_cve_2012_5468(self):
        '''Test CVE-2012-5468'''

        script = os.path.join(self.tempdir, "cve_2012_5468.mbox")
        contents = '''Content-Type: multipart/mixed;boundary="----=_20121014031204_57463"

------=_20121014031204_57463
Content-Type: text/plain; charset="utf-8"

------=_20121014031204_57463
Content-Transfer-Encoding: base64

'''

        contents += "vfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvfvf\n" * 600
        contents += "------=_20121014031204_57463--"

        testlib.create_fill(script, contents, mode=0755)

        rc, report = testlib.cmd(['bogofilter', '-vv', '-d', self.tempdir, '-B', script])
        expected = 2
        result = 'Got exit code %d, expected %d\n' % (rc, expected)
        self.assertEquals(expected, rc, result + report)

if __name__ == '__main__':
    testlib.require_sudo()
    unittest.main()
