To run individual tests out of openjdk-6, a full build is not needed (you can test the locally installed JDK).

# prepare/patch the build directory
cd /tmp
sudo apt-get build-dep openjdk-6
sudo apt-get install openjdk-6-jdk
apt-get source openjdk-6
cd openjdk-6-*
fakeroot debian/rules patch
cd build

# prepare the testsuite
mkdir -p test/jtreg/classes

1.11 and older:
javac -g -d test/jtreg/classes -source 1.5 -encoding iso-8859-1 `find $(pwd)/../test/jtreg/com -name '*.java'` # old
cd ../test/jtreg

1.12 and higher:
javac -g -d test/jtreg/classes -source 5 -target 6 -encoding iso-8859-1 `find $(pwd)/../src/jtreg/com -name '*.java'` # 1.12+
cd ../src/jtreg

All versions:
jar cfm ../../build/test/jtreg.jar META-INF/MANIFEST.MF legal  README JavaTest.cmdMgrs.lst JavaTest.toolMgrs.lst `find com -type f -a -not -name '*.java'` -C ../../build/test/jtreg/classes com
cd ../../build

# run tests
rm -rf test/hotspot/JTwork test/hotspot/JTreport

1.11 and older:
java -jar test/jtreg.jar -v1 -a -ignore:quiet -w:test/hotspot/JTwork -r:test/hotspot/JTreport -jdk:/usr/lib/jvm/java-6-openjdk -s -exclude:$(pwd)/../test/jtreg/excludelist.jdk.jtx \
    openjdk/jdk/test/TEST_PATH_HERE (e.g. openjdk/jdk/test/java/awt/grab/EmbeddedFrameTest1/EmbeddedFrameTest1.java)

1.12 and higher:
java -jar test/jtreg.jar -v1 -a -ignore:quiet -w:test/hotspot/JTwork -r:test/hotspot/JTreport -jdk:/usr/lib/jvm/java-6-openjdk-amd64 -s -exclude:$(pwd)/../src/jtreg/excludelist.jdk.jtx \
    openjdk/jdk/test/TEST_PATH_HERE (e.g. openjdk/jdk/test/java/awt/grab/EmbeddedFrameTest1/EmbeddedFrameTest1.java)

# then look in test/hotspot/JTwork tree for output.

May want to pull the test cases out and work on them individually. Eg:
$ cp path/to/ListTest.java /tmp
$ cd /tmp
$ CLASSPATH="/usr/lib/jvm/java-6-openjdk-amd64/lib:/usr/lib/jvm/java-6-openjdk-amd64/lib/tools.jar:." javac ListTest.java
$ CLASSPATH="/usr/lib/jvm/java-6-openjdk-amd64/lib:/usr/lib/jvm/java-6-openjdk-amd64/lib/tools.jar:." java ListTest

openjdk-7
---------

# prepare/patch the build directory
Same as above, but use this after running 'fakeroot debian/rules patch':
cd build
make patch

# prepare the testsuite
Same as above, but use this javac command:
javac -g -encoding utf-8 -source 7 -target 7 -d test/jtreg/classes `find $(pwd)/../test/jtreg/com -name '*.java'`

# run tests
rm -rf test/hotspot/JTwork test/hotspot/JTreport
# use -jdk:/usr/lib/jvm/java-7-openjdk-amd64 on amd64
java -jar test/jtreg.jar -v1 -a -ignore:quiet -w:test/hotspot/JTwork -r:test/hotspot/JTreport -jdk:/usr/lib/jvm/java-7-openjdk-i386 -s -exclude:$(pwd)/../test/jtreg/excludelist.jdk.jtx openjdk/jdk/test/TEST_PATH_HERE (e.g. openjdk/jdk/test/java/rmi/registry/readTest/readTest.sh)
cd ../../build

# then look in test/hotspot/JTwork and test/hotspot/JTreport tree for output.

Note, if the test doesn't run, look to see if it is in the excludelist we
specified.
