python-django has an extensive test suite that is run during build.
Make sure to check build logs.

There is a test script in QRT called qrt-django.py.

MAAS extensively uses python-django. Make sure the MAAS test suite is run.

To run the maas test suite:
(needs firefox for some of the tests, so need to run in a desktop session)

Needs at least 2Gb of ram in the vm.

sudo apt-get build-dep maas
sudo apt-get install python-paramiko
sudo apt-get install virtualenv (utopic+)
apt-get source maas
cd maas*
sudo make install-dependencies
make test

Maas in Ubuntu 15.04 and Ubuntu 15.10 uses a different python-django
package in the archive called python-django16. The test procedure doesn't
work to test the python-django16 package.

More info:
https://maas.ubuntu.com/docs/hacking.html
