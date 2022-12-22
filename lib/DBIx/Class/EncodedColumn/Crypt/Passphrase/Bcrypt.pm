package DBIx::Class::EncodedColumn::Crypt::Passphrase::Bcrypt;

# ABSTRACT: Crypt::Passphrase::Bcrypt backend

use strict;
use warnings;

our $VERSION = '0.0101';

use Encode qw(encode_utf8);
use Crypt::Passphrase::Bcrypt;

sub make_encode_sub {
  my($class, $col, $args) = @_;

  my $cost = exists $args->{cost} ? $args->{cost} : 8;
  die("Valid cost is a 1 or 2 digit integer. You used '${cost}'.")
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

  my $cost = exists $args->{cost} ? $args->{cost} : 8;
  die("Valid cost is a 1 or 2 digit integer. You used '${cost}'.")
    unless $cost =~ /^\d\d?$/;
  $cost = sprintf '%02i', 0 + $cost;

  my $passphrase = Crypt::Passphrase::Bcrypt->new(
    cost => $cost,
  );

  return sub {
    my $col_v = $_[0]->get_column($col);
    return unless defined $col_v;
    return $passphrase->verify_password(encode_utf8($_[1]), $col_v);
  }
}

1;

__END__;

=head1 SYNOPSIS

  # Crypt::Passphrase::Bcrypt / cost of 6 / generate check method:

  __PACKAGE__->add_columns(
    password => {
      data_type           => 'CHAR',
      size                => 255,
      encode_column       => 1,
      encode_class        => 'Crypt::Passphrase::Bcrypt',
      encode_args         => { cost => 6 },
      encode_check_method => 'check_password',
  });

=head1 DESCRIPTION

Use L<Crypt::Passphrase::Bcrypt> for an encoded password column.

=head1 ENCODE ARGUMENTS

=head2 cost => \d\d?

A single or double digit non-negative integer representing the cost of the
hash function. Defaults to C<8>.

=head1 METHODS

=head2 make_encode_sub $column_name, \%encode_args

Returns a coderef that accepts a plain text value and returns an encoded value

=head2 make_check_sub $column_name, \%encode_args

Returns a coderef that when given the row object and a plain text value will
return a boolean if the plain text matches the encoded value. This is typically
used for password authentication.

=head1 SEE ALSO

L<Crypt::Passphrase>

L<DBIx::Class::EncodedColumn>,

=cut
