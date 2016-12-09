#!/usr/bin/perl
#    bindings.pl quality assurance test script for apparmor
#    Copyright (C) 2011 Canonical Ltd.
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

use strict;
use warnings;

require LibAppArmor;

@ARGV == 1 or die "bindings.pl <messages file>\n";

my $messages = "";
{
  local $/=undef;
  open FILE, $ARGV[0] or die "Couldn't open file: $!";
  $messages = <FILE>;
  close FILE;
}

my $error = "no";

foreach my $msg (split(/\n/, $messages)) {
    my($test) = LibAppArmorc::parse_record($msg);

    print "Audit ID: " . LibAppArmor::aa_log_record::swig_audit_id_get($test) . "\n";
    print "PID: " . LibAppArmor::aa_log_record::swig_pid_get($test) . "\n";
    print "Epoch: " . LibAppArmor::aa_log_record::swig_epoch_get($test) . "\n";
    print "Operation: " . LibAppArmor::aa_log_record::swig_operation_get($test) . "\n";
    print "Name: " . LibAppArmor::aa_log_record::swig_name_get($test) . "\n";
    print "Denied mask: " . LibAppArmor::aa_log_record::swig_denied_mask_get($test) . "\n";

    if (LibAppArmor::aa_log_record::swig_event_get($test) == $LibAppArmor::AA_RECORD_ALLOWED )
    {
        print "Testing AA_RECORD_ALLOWED (" . $LibAppArmor::AA_RECORD_ALLOWED . ")\n";
    }
    elsif (LibAppArmor::aa_log_record::swig_event_get($test) == $LibAppArmor::AA_RECORD_DENIED )
    {
        print "Testing AA_RECORD_DENIED (" . $LibAppArmor::AA_RECORD_DENIED . ")\n";
    }
    else
    {
        print "Bad event: " . LibAppArmor::aa_log_record::swig_event_get($test) . "\n";
        $error = "yes";
    }

    LibAppArmorc::free_record($test);

    print "\n";
}

if ($error ne "no") {
    print "Result: FAIL\n";
    exit 1;
}

print "Result: pass\n";
exit 0;
