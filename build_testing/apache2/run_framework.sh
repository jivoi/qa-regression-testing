#!/bin/sh -e

if [ "$USER" = "root" ]; then
    echo "Please don't run this script as root." >&2
    exit 1
fi

# Increase the timeout
export APACHE_TEST_STARTUP_TIMEOUT=360

rm -rf ./httpd-framework
tmp=`mktemp`
logfile="`pwd`/run_framework.log"
mv -f $tmp "$logfile"

release=`lsb_release -c | awk '{print $2}'`
echo "Installing packages" | tee -a "$logfile"
sudo apt-get -y --force-yes install libcrypt-ssleay-perl libdevel-symdump-perl perl-modules perl libhtml-tagset-perl libhtml-parser-perl libwww-perl libipc-run3-perl libhttp-dav-perl make netbase patch >> "$logfile"

if [ "$release" = "dapper" ] || [ "$release" = "hardy" ] || [ "$release" = "karmic" ]; then
    sudo apt-get -y --force-yes install libdevel-corestack-perl
fi

for i in apache2-mpm-prefork apache2-mpm-worker apache2-mpm-event apache2-mpm-perchild apache2-mpm-itk ; do
    echo "Installing apache packages for '$i'" | tee -a "$logfile"
    if [ "$i" = "apache2-mpm-prefork" ]; then
        packages="$i apache2-prefork-dev libapache2-mod-php5"
    elif [ "$i" = "apache2-mpm-worker" ]; then
        packages="$i apache2-threaded-dev"
    else
        packages="apache2-threaded-dev"
        if [ "$i" = "apache2-mpm-perchild" ]; then
            if [ "$release" = "dapper" ] || [ "$release" = "hardy" ]; then
                packages="$packages $i"
            else
                echo "Skipping '$i' for $release" | tee -a "$logfile"
                continue
            fi
        else
            if [ "$release" = "dapper" ]; then
                echo "Skipping '$i' for $release" | tee -a "$logfile"
                continue
            fi
            packages="$packages $i"
        fi
    fi
    sudo apt-get -y --force-yes install $packages >> "$logfile" 2>&1

    version=`dpkg-query -W -f='${Version}\n' $i`
    output="`pwd`/$release-$version-$i.txt"
    do_test="yes"
    if [ -s "$output" ]; then
        echo -n "'$output' already exists. Overwrite (y|N)? "
        read ans
        if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then
            do_test="no"
            continue
        fi
    fi

    echo "Unpacking" | tee -a "$logfile"
    tar -zxf ./httpd-framework*tar.gz >> "$logfile"

    echo "Patching" | tee -a "$logfile"
    cd httpd-framework
    patch -p1 < ../httpd-framework-ifversion.patch >> "$logfile"
    patch -p1 < ../httpd-framework-debian-apxs.patch >> "$logfile"

    echo "Updating configuration" | tee -a "$logfile"
    if [ "$release" = "dapper" ]; then
        sudo ../fix-apache2-conf-dapper.sh >> "$logfile" 2>&1 || true
    else
        sudo ../fix-apache2-conf-gutsy.sh >> "$logfile" 2>&1 || true
    fi

    if [ "$do_test" = "yes" ]; then
        echo "Running test for '$i'" | tee -a "$logfile"
        perl ./Makefile.PL -apxs /usr/bin/apxs2 >> "$logfile" 2>&1
        set +e
        make test > "../$release-$version-$i.txt" 2>&1 || echo "*** TESTS EXITED WITH ERROR: $?" | tee -a "$logfile"
        set -e
    else
        echo "Skipping test for '$i'" | tee -a "$logfile"
    fi

    cd ..
    rm -rf ./httpd-framework
done

echo ""
echo "Tests complete, see $logfile for details"

