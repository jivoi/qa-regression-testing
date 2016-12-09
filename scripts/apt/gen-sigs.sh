#!/bin/sh
#
#    gensigs.sh
#    Copyright (C) 2009 Canonical Ltd.
#    Author: Micael Vogt <michael.vogt@canonical.com>
#            Jamie Strandboge <jamie@canonical.com>
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

# To sign with a revoked key, use:
# gpg --keyring ../keyring/pubring.gpg.not-yet-revoked --secret-keyring ../keyring/secring.gpg.not-yet-revoked --default-key revoked-key@example.com -o - -a -b -s ./Release >> ./Release.gpg
#
# To sign with an expired key (will have to adjust days), use:
# faketime '365 days ago' gpg --homedir ../keyring --default-key expired-key@example.com -o - -a -b -s ./Release >> ./Release.gpg

# some other invocations:
gpg --homedir ./keyring/ \
    --default-key expired-key@example.com  \
    -o ./repo-expired/Release.gpg \
    -a -b -s repo-expired/Release 


gpg --homedir ./keyring/ \
    --default-key good-key@example.com  \
    -o ./repo-good/Release.gpg \
    -a -b -s repo-good/Release 

gpg --homedir ./keyring/ \
    --default-key revoked-key@example.com  \
    -o ./repo-revoked/Release.gpg \
    -a -b -s repo-revoked/Release 

gpg --homedir ./keyring/ \
    --default-key good-key@example.com  \
    -o - \
    -a -b -s repo-expired-and-valid/Release \
    >> ./repo-expired-and-valid/Release.gpg 

gpg --homedir ./keyring/ \
    --default-key good-key@example.com  \
    -o - \
    -a -b -s repo-revoked-and-valid/Release \
    >> ./repo-revoked-and-valid/Release.gpg 
