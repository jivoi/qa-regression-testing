json-c on saucy+ builds a runs a small test suite during build, see the
build logs for something like:

============================================================================
Testsuite summary for json-c 0.11
============================================================================
# TOTAL: 11
# PASS:  11
# SKIP:  0
# XFAIL: 0
# FAIL:  0
# XPASS: 0
# ERROR: 0
============================================================================

For precise:

sudo apt-get build-dep json-c
sudo apt-get install devscripts
apt-get source json-c
cd json-c-0.9
debuild
./test1 > /tmp/test1.out
./test2 > /tmp/test2.out
./test3 reads a json file from stdin, don't test for now

-----------------------

fwts uses json-c, and has a test suite. To run:

sudo apt-get build-dep fwts
sudo apt-get install devscripts
apt-get source fwts
cd fwts-*
debuild
make check

Must run after updating installed json-c packages (duh!)

Can also run fwts itself:
sudo apt-get install fwts
sudo fwts --log-type json


----------------------

On Saucy+, upstart also uses json-c. To run the test suite:


sudo apt-get build-dep upstart
sudo apt-get install devscripts
apt-get source upstart
cd upstart-*
debuild
make check > /tmp/output.txt

You can test if upstart respawns itself with "telinit u"


