# Last Modified: Mon Jan  9 16:11:27 2012
#include <tunables/global>

@{HOME}/tmp/aa/ux/python/bin/exe_python3 {
  #include <abstractions/base>
  #include <abstractions/python>
  @{HOME}/tmp/aa/ux/python/bin/exe_python3 r,
  @{HOME}/tmp/aa/ux/python/bin/child3.py Uxr,
  @{HOME}/tmp/aa/ux/python/TestPython/* r,
  deny @{HOME}/tmp/aa/ux/python/**/*.pyc w,
  deny @{HOME}/tmp/aa/ux/python/**/__pycache__/ w,
  /bin/dash ixr,
  /usr/bin/python* ix,

  # noise
  deny @{HOME}/.local/lib/python3.2/site-packages/ r,
  /etc/default/apport r,
  /etc/apt/apt.conf.d/ r,
  /etc/apt/apt.conf.d/** r,
  /usr/include/python*/pyconfig.h r,
  deny /usr/local/lib/python*/dist-packages/ r,
  /usr/share/pyshared/* r,
  /etc/python*/** r,
}
