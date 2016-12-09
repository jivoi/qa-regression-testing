#!/usr/bin/env python
from __future__ import print_function
import sys
try:
    f = open(sys.argv[1])
    f.read(int(sys.argv[2]))
    f.close()
except IOError as e:
    print("%s: %s" % (sys.argv[1], e.strerror), file=sys.stderr)
    sys.exit(e.errno)
print("%s: Success" % (sys.argv[1]))
sys.exit(0)
