How to test paste un Lucid:

- Unpack the source, apply patches
- Apply lucid.patch from the current directory

Open a Lucid schroot, perform the following steps:

- sudo apt-get install python-codespeak-lib python-virtualenv python-nose
- cd paste-1.7.2
- mkdir tests/test_exceptions/reporter_output
- virtualenv ../xx
- source ../xx/bin/activate
- python setup.py test
