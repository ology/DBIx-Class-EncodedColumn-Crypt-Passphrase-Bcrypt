package DBIx::Class::EncodedColumn::Crypt::Passphrase::Bcrypt;

# ABSTRACT: Crypt::Passphrase::Bcrypt backend

use strict;
use warnings;

our $VERSION = '0.0100';

use Crypt::Passphrase::Bcrypt;

our $VERSION = '0.0100';

sub make_encode_sub {
  my($class, $col, $args) = @_;

  my $cost = exists $args->{cost} ? $args->{cost} : 8;
  die("Valid costs are 1 or 2 digit integers. You used '${cost}'.")
    unless $cost =~ /^\d\d?$/;
  $cost = sprintf '%02i', 0 + $cost;

  my $passphrase = Crypt::Passphrase::Bcrypt->new(
    cost => $cost,
  );

  my $encoder = sub {
    my ($plain_text) = @_;
    return $passphrase->hash_password($plain_text);
  };

  return $encoder;
}

sub make_check_sub {
  my($class, $col, $args) = @_;

  #fast fast fast
  return eval qq^ sub {
    my \$col_v = \$_[0]->get_column('${col}');
    return unless defined \$col_v;
    \$_[0]->verify_password->{${col}}->(\$_[1], \$col_v) eq \$col_v;
  } ^ || die($@);
}

1;

__END__;

=head1 SYNOPSYS

  # Crypt::Passphrase::Bcrypt / cost of 6 / generate check method
  __PACKAGE__->add_columns(
    password => {
      data_type           => 'CHAR',
      size                => 255,
      encode_column       => 1,
      encode_class        => 'Crypt::Passphrase::Bcrypt',
      encode_args         => { cost => 6 },
      encode_check_method => 'verify_password',
  });

=head1 DESCRIPTION

Use L<Crypt::Passphrase::Bcrypt> for an encoded password column.

=head1 ENCODE ARGUMENTS

=head2 cost => \d\d?

A single or double digit non-negative integer representing the cost of the
hash function. Defaults to C<8>.

=head1 METHODS

=head2 make_encode_sub $column_name, \%encode_args

Returns a coderef that accepts a plaintext value and returns an encoded value

=head2 make_check_sub $column_name, \%encode_args

Returns a coderef that when given the row object and a plaintext value will
return a boolean if the plaintext matches the encoded value. This is typically
used for password authentication.

=head1 SEE ALSO

L<Crypt::Passphrase>

L<DBIx::Class::EncodedColumn>,

=cut
