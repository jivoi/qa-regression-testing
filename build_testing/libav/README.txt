libav has a test suite called "fate".
(ffmpeg on Lucid doesn't)

See:
http://libav.org/fate.html

Steps to run:

- $ sudo apt-get build-dep libav
- $ sudo apt-get install devscripts quilt
- unpack source
- apply patches
- inside source tree: rsync -aL rsync://fate-suite.libav.org/fate-suite/ fate-suite
  (may keep the fate-suite directory for future tests)
- $ ./configure --samples=fate-suite
- $ make fate > /tmp/results.txt 2>&1
- $ make fate > /tmp/results.txt 2>&1 (second time gets rid of compile messages)

IMPORTANT:
- Check the number of tests performed to make sure the fate test suite was
  included properly. For example, on Precise, the results file should have
  about 302 tests if fate is missing, and about 992 tests if fate was
  properly configured.
