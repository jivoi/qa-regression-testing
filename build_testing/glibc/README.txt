How to unpack and apply patches on hardy's insane package:

make -f debian/rules unpack
cd build-tree/glibc-2.7
export QUILT_PATCHES=../../debian/patches/
quilt push -a

Hardy's glibc has sporadic test suite failures when building.

