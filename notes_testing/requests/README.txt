The requests package comes with a test script called "test_requests.py"
which is not run at build time.

To test:
$ sudo apt-get build-dep requests
$ sudo apt-get install devscripts python-pytest python3-pytest
$ apt-get source requests
$ cd requests*
$ ./test_requests.py -v
$ python3 ./test_requests.py -v
