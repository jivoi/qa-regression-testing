# Last Modified: Mon Jan  9 15:54:17 2012
#include <tunables/global>

@{HOME}/tmp/aa/ux/perl/exe_perl {
  #include <abstractions/base>
  #include <abstractions/perl>

  /home/*/tmp/aa/ux/perl/Testlib/Stuff.pm r,
  /home/*/tmp/aa/ux/perl/exe_perl r,
  /usr/bin/perl ix,

  #include <abstractions/ubuntu-helpers>
  #@{HOME}/tmp/aa/ux/perl/child.pl Ux,
  @{HOME}/tmp/aa/ux/perl/child.pl Cx -> sanitized_helper,
}
