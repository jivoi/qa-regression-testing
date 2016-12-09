package Testlib::Stuff;

require Exporter;
our @ISA    = qw(Exporter);
our @EXPORT = qw(
    print_msg
);

sub print_msg() {
    print "Ok\n";
}

