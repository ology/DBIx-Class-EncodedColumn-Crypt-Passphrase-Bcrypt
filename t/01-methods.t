#!/usr/bin/env perl
use strict;
use warnings;

use Test::More;

use_ok 'DBIx::Class::EncodedColumn::Crypt::Passphrase::Bcrypt';

new_ok 'DBIx::Class::EncodedColumn::Crypt::Passphrase::Bcrypt';

my $obj = new_ok 'DBIx::Class::EncodedColumn::Crypt::Passphrase::Bcrypt' => [
    verbose => 1,
];

is $obj->verbose, 1, 'verbose';

done_testing();
