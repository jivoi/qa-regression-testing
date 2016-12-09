# Last Modified: Mon Jan  9 16:11:27 2012
#include <tunables/global>

@{HOME}/tmp/aa/ux/python/bin/exe_python {
  #include <abstractions/base>
  #include <abstractions/python>
  /etc/default/apport r,
  /etc/apt/apt.conf.d/ r,
  /etc/apt/apt.conf.d/** r,
  @{HOME}/tmp/aa/ux/python/bin/exe_python r,
  @{HOME}/tmp/aa/ux/python/bin/child.py Uxr,
  /bin/dash ixr,
  /home/*/tmp/aa/ux/python/TestPython/* r,
  /usr/bin/python* ix,
  /usr/include/python*/pyconfig.h r,
  deny /usr/local/lib/python*/dist-packages/ r,
  /usr/share/pyshared/* r,

}
