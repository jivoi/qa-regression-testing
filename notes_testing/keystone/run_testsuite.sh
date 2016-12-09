#!/bin/sh

# Run testsuite (should compare to debian/rules)

CURDIR=`pwd`

prepare_testsuite_precise() {
        # create a dummy db for testing
        rm -rf "$CURDIR"/debian/tests/testing.db
        migrate version_control sqlite:////"$CURDIR"/debian/tests/testing.db \
                "$CURDIR"/keystone/common/sql/migrate_repo
        # run migrations
        PYTHONPATH="$CURDIR"  migrate upgrade \
                sqlite:////"$CURDIR"/debian/tests/testing.db \
                "$CURDIR"/keystone/common/sql/migrate_repo

        # tests/test_overrides.conf can be used to setup the environment
        # for unit testing.
        cp tests/test_overrides.conf tests/test_overrides.conf.orig
        cp "$CURDIR"/debian/tests/test_overrides.conf "$CURDIR"/tests/test_overrides.conf
        sed -i "s|%CUR_DIR%|$CURDIR|g" "$CURDIR"/tests/test_overrides.conf

        cat <<EOM
Testsuite it prepared. Run with:
$ bash run_tests.sh -N
$ bash run_tests.sh -N test_....py
EOM
}

prepare_testsuite_raring() {
        # Just copy in our overrides
        cp tests/test_overrides.conf tests/test_overrides.conf.orig
        cp "$CURDIR"/debian/tests/test_overrides.conf "$CURDIR"/tests/test_overrides.conf
        cat <<EOM
Testsuite it prepared. Run with:
$ PYTHONPATH="$CURDIR" bash run_tests.sh -N
$ PYTHONPATH="$CURDIR" bash run_tests.sh -N test_....py
EOM
}

prepare_testsuite_saucy() {
        # Nothing weird for saucy, overrides are applied via quilt
        cat <<EOM
Testsuite it prepared. Run with:
$ PYTHONPATH="$CURDIR" bash run_tests.sh -N
$ PYTHONPATH="$CURDIR" bash run_tests.sh -N test_....py

Or to run in a virtualenv (TODO: this doesn't work right):
$ sudo apt-get install python-virtualenv python-dev libxml2-dev libxslt1-dev libsasl2-dev libsqlite3-dev libssl-dev libldap2-dev
$ PYTHONPATH="$CURDIR" bash run_tests.sh -V
$ PYTHONPATH="$CURDIR" bash run_tests.sh -V --force    # force clean of venv
$ PYTHONPATH="$CURDIR" bash run_tests.sh -V test_....py
EOM
}

usage() {
    echo "`basename $0` precise|quantal|raring|saucy"
}

if [ -z "$1" ]; then
    usage
    exit 1
fi

# Make sure in toplevel unpacked source
if [ ! -f debian/rules ]; then
    echo "Could not find debian/rules. Make sure you are in the toplevel"
    echo "unpacked source. Aborting"
    exit 1
fi

cat <<EOM
Warning: this copies the code from debian/rules for the specifies release
         for running the testsuite. This should not typically be done in the
         toplevel source you are preparing for updating, as it does not
         perform any cleanup.
EOM
echo -n "Proceed (y|N)? "
read ans

if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then
    echo "Aborting"
    exit 1
fi

case "$1" in
    precise)
        prepare_testsuite_precise
        ;;
    quantal)
        prepare_testsuite_precise
        ;;
    raring)
        prepare_testsuite_raring
        ;;
    saucy)
        prepare_testsuite_saucy
        ;;
    *)
        usage
        exit 1
        ;;
esac
