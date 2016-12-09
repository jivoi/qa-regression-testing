Running the test suite:

In a VM, do:

sudo apt-get build-dep telepathy-idle
sudo apt-get install python-twisted-words

./configure --prefix=/usr
make
make check

Make sure the twisted tests are being run

