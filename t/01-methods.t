#!/usr/bin/env perl
use strict;
use warnings;
use utf8;

use Encode qw(encode_utf8);
use Test::More;
use Test::SQLite;

use lib 't/lib';
use Schema;

use_ok 'DBIx::Class::EncodedColumn::Crypt::Passphrase::Bcrypt';

my $sqlite = Test::SQLite->new;

my $schema = Schema->connect($sqlite->dsn, '', '');
isa_ok $schema, 'Schema';

$schema->deploy;

my $result = $schema->resultset('Bcrypt')->create({
  id       => 1,
  bcrypt_1 => 'test1',
  bcrypt_2 => 'test1',
});
isa_ok $result, 'Schema::Result::Bcrypt';

ok !$result->bcrypt_1_check('bogus'), 'encode failure';
ok !$result->bcrypt_2_check('bogus'), 'encode failure';

ok $result->bcrypt_1_check('test1'), 'encode_check_method';
ok $result->bcrypt_2_check('test1'), 'encode_check_method';

$result->bcrypt_1('test2');
$result->bcrypt_2('test2');
ok $result->bcrypt_1_check('test2'), 'encode_check_method';
ok $result->bcrypt_2_check('test2'), 'encode_check_method';

$result->bcrypt_1(encode_utf8('官话'));
$result->update;
ok $result->bcrypt_1_check('官话'), 'encode_check_method';

$result->bcrypt_1(undef);
$result->bcrypt_2(undef);
is $result->bcrypt_1, undef, 'is undef';
is $result->bcrypt_2, undef, 'is undef';
ok !$result->bcrypt_1_check(undef), 'encode_check_method fails for undef';
ok !$result->bcrypt_2_check(undef), 'encode_check_method fails for undef';

done_testing();
