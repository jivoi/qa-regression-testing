libcommons-fileupload-java in saucy and later runs the test suite at
build time, so make sure the logs are checked for any new failures.

To manually run the test suite in precise to raring:

sudo apt-get build-dep libcommons-fileupload-java
apt-get source libcommons-fileupload-java

cd libcommons-fileupload-java*
mvn test


To manually run the test suite in lucid:

sudo apt-get build-dep libcommons-fileupload-java
sudo apt-get install junit ubuntu-dev-tools
apt-get source libcommons-fileupload-java

cd libcommons-fileupload-java*
make -f debian/rules patch
ant
ant test


