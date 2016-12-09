#!/bin/sh

set -e

tmpdir=`mktemp -d`
trap "rm -rf $tmpdir" EXIT HUP INT QUIT TERM

# create the script
cat > $tmpdir/dac.sh <<EOM
#!/bin/sh

mkdir $tmpdir/foo 2>/dev/null || true
echo stuff > $tmpdir/foo/bar
EOM
chmod 755 $tmpdir/dac.sh

# create the profiles
cat > $tmpdir/profile_no_dac <<EOM
#include <tunables/global>

$tmpdir/dac.sh {
  #include <abstractions/base>

  /bin/dash rix,
  /bin/mkdir rix,
  $tmpdir/dac.sh r,

  $tmpdir/ rw,
  $tmpdir/foo/ rw,
  $tmpdir/foo/** rw,
}
EOM

cat > $tmpdir/profile_dac <<EOM
#include <tunables/global>

$tmpdir/dac.sh {
  #include <abstractions/base>

  capability dac_override,

  /bin/dash rix,
  /bin/mkdir rix,
  $tmpdir/dac.sh r,

  $tmpdir/foo/ rw,
  $tmpdir/foo/** rw,
}
EOM

cat > $tmpdir/profile_dac_noaccess <<EOM
#include <tunables/global>

$tmpdir/dac.sh {
  #include <abstractions/base>

  capability dac_override,

  /bin/dash rix,
  /bin/mkdir rix,
  $tmpdir/dac.sh r,

  $tmpdir/foo/ rw,
}
EOM

for p in profile_no_dac profile_dac profile_dac_noaccess ; do
    echo "Trying $p"
    cat $tmpdir/$p | sudo apparmor_parser -r >/dev/null
    rm -rf $tmpdir/foo || true
    mkdir $tmpdir/foo
    touch $tmpdir/foo/bar
    chmod 644 $tmpdir/foo/bar
    sleep 3
    if $tmpdir/dac.sh 2>/dev/null ; then
        echo "dac.sh (0644 $p): access"
    else
        echo "dac.sh (0644 $p): noaccess"
    fi
    chmod 0 $tmpdir/foo/bar
    if $tmpdir/dac.sh 2>/dev/null ; then
        echo "dac.sh (0000 $p): access"
    else
        echo "dac.sh (0000 $p): noaccess"
    fi

    if sudo $tmpdir/dac.sh 2>/dev/null ; then
        echo "sudo dac.sh (0000 $p): access"
    else
        echo "sudo dac.sh (0000 $p): noaccess"
    fi
done

echo $tmpdir
