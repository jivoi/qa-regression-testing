How to run the libxml-security-java test suite on lucid:

sudo apt-get build-dep libxml-security-java
sudo apt-get install junit
apt-get source libxml-security-java
cd libxml-security-java*
rm -rf libs
ln -s /usr/share/java libs
sed -i "s/xalan.jar/xalan2.jar/" build.xml

ant compile
ant test


