xdelta3 contains a built-in test suite in the actual binary itself.

Required the ncompress package be installed for the "compress" binary:

$ sudo apt-get install ncompress

Must _not_ be root to run it, and must specify the full path to the
binary:

$ /usr/bin/xdelta3 test

