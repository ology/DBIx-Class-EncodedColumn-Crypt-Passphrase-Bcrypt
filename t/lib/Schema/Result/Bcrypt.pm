package # hide from PAUSE
    Schema::Result::Bcrypt;
 
use strict;
use warnings;

use base 'DBIx::Class::Core';

__PACKAGE__->load_components(qw/EncodedColumn Core/);
__PACKAGE__->table('bcrypt');
__PACKAGE__->add_columns(
  id => {
    data_type         => 'int',
    is_nullable       => 0,
    is_auto_increment => 1
  },
  bcrypt_1 => {
    data_type           => 'text',
    is_nullable         => 1,
    size                => 60,
    encode_column       => 1,
    encode_class        => 'Crypt::Passphrase::Bcrypt',
    encode_check_method => 'bcrypt_1_check',
  },
  bcrypt_2 => {
    data_type           => 'text',
    is_nullable         => 1,
    size                => 59,
    encode_column       => 1,
    encode_class        => 'Crypt::Passphrase::Bcrypt',
    encode_args         => { cost => 6 },
    encode_check_method => 'bcrypt_2_check',
  },
);

__PACKAGE__->set_primary_key('id');

1;
