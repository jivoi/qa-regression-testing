#!/usr/bin/python
#    bindings.py quality assurance test script for apparmor
#    Copyright (C) 2011-2012 Canonical Ltd.
#    Author: Jamie Strandboge <jamie@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import LibAppArmor

if len(sys.argv) != 2:
    print("%s <messages file>" % os.path.basename(sys.argv[0]))
    sys.exit(1)
messages = open(sys.argv[1]).read()

error = False

for msg in messages.splitlines():
    test = LibAppArmor.parse_record(msg)
    print("Audit ID: %s" % LibAppArmor._LibAppArmor.aa_log_record_audit_id_get(test))
    print("PID: %d" % LibAppArmor._LibAppArmor.aa_log_record_pid_get(test))
    print("Epoch: %d" % LibAppArmor._LibAppArmor.aa_log_record_epoch_get(test))
    print("Operation: %s" % LibAppArmor._LibAppArmor.aa_log_record_operation_get(test))
    print("Name: %s" % LibAppArmor._LibAppArmor.aa_log_record_name_get(test))
    print("Denied mask: %s" % LibAppArmor._LibAppArmor.aa_log_record_denied_mask_get(test))

    if LibAppArmor._LibAppArmor.aa_log_record_event_get(test) == LibAppArmor.AA_RECORD_ALLOWED:
        print("Testing AA_RECORD_ALLOWED (%d)" % LibAppArmor.AA_RECORD_ALLOWED)
    elif LibAppArmor._LibAppArmor.aa_log_record_event_get(test) == LibAppArmor.AA_RECORD_DENIED:
        print("Testing AA_RECORD_DENIED (%d)" % LibAppArmor.AA_RECORD_DENIED)
    else:
        print("Bad event: %d" % LibAppArmor._LibAppArmor.aa_log_record_event_get(test))
        error = True

    LibAppArmor.free_record(test)
    print("")

if error:
    print("Result: FAIL")
    sys.exit(1)

print("Result: pass")
sys.exit(0)
