#!/usr/bin/env python
#
#    simple-eavesdrop-addmatch.py simple program that adds an eavesdrop match string
#    Copyright (C) 2013 Canonical Ltd.
#    Author: Tyler Hicks <tyhicks@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 2,
#    as published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
import dbus

if __name__ == '__main__':
    session_bus = dbus.SessionBus()
    try:
        session_bus.add_match_string("eavesdrop='true',type='method_call'")
        session_bus.add_match_string("eavesdrop='true',type='method_return'")
        session_bus.add_match_string("eavesdrop='true',type='signal'")
        session_bus.add_match_string("eavesdrop='true',type='error'")
    except Exception, e:
        print >> sys.stderr, "Failed to add match string: %s" % str(e)
        sys.exit(1)
