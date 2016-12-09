The built-in Perl tests should provide reasonable coverage.  Security
build logs should be compared against the prior release's build log to
detect any changes in test output.

The Memoize module test cases are race conditions -- when it fails, retry
the build before investigating further.

Hardy and Lucid perl patches must be applied before building; the
directory debian/patches/ is primarily for documenting what was applied.
Do not follow the advice to ./debian/rules unpatch the tree before working
on patches -- the patch must apply to the tree in the correct order for
./debian/rules patch and ./debian/rules unpatch to work. Don't bother
using ./debian/rules (un)patch while working on the patch, just test it
once at the end.

Oneiric and newer Perl packages have the patches appplied, but they're
managed with quilt, so it is straightforward.
